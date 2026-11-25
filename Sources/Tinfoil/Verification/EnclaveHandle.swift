import Foundation

/// One attested enclave's verification state: it verifies the enclave and
/// keeps the result until it expires or the caller asks for a fresh one. It
/// sends no requests; `EnclaveConnection` ties traffic to the keys that it
/// verifies.
///
/// Each `reverify()` is one run. A run fetches the enclave's attestation
/// document and has the TinfoilGo verifier check it, retrying a failed
/// attempt once. Every attempt, retried or final, becomes
/// `lastVerificationAttempt` as soon as its outcome is decided, and is
/// reported to `onVerificationAttempt` once the run is done, outside the
/// actor. A run that fails attestation withdraws the verification that it was
/// replacing from `usable`, so that no later request uses it, and so does a
/// key rejection, through `discard(_:)`.
actor EnclaveHandle {
    nonisolated let enclave: String
    nonisolated let pin: Pin
    private let attestationRelay: String?
    private let attestor: Attestor
    private let onVerificationAttempt: VerificationCallback?
    /// Whether a verification must endorse an HPKE key, as one for EHBP
    /// must; an attempt whose document endorses none fails
    private let requiresHPKEKey: Bool
    private let now: @Sendable () -> Date
    /// The verification in progress, shared by every caller that asks while
    /// it runs
    private var inFlight: Task<VerificationReport, Error>?
    /// The failed attempts that the run in progress retried, in order, kept
    /// until the run reports them
    private var retried: [TinfoilError] = []
    private var closed = false

    /// The outcome of the most recent attempt, or nil before the first: a
    /// report that passed, or the error that the attempt failed with. A
    /// failure replaces an earlier success. A report may have expired or
    /// been discarded since; `ensureVerified()` returns one that is valid
    /// now.
    private(set) var lastVerificationAttempt: Result<VerificationReport, TinfoilError>?
    /// The verification that requests may use: the last that passed, or nil
    /// before the first, after a run that fails attestation discards it, and
    /// after the enclave rejects its key.
    /// It may have expired; `ensureVerified()` returns one that has not.
    private(set) var usable: VerificationReport?

    /// The report of the verification that requests are bound to now: the
    /// usable verification while it is before its `freshnessExpiresAt`, and
    /// otherwise nil. It verifies nothing.
    var currentVerification: VerificationReport? {
        guard let usable, now() < usable.freshnessExpiresAt else {
            return nil
        }
        return usable
    }
    /// Counts the verifications that have become `usable`, so that a failed
    /// run discards only the one that it was replacing
    private var generation: UInt64 = 0

    /// - Parameter initial: A verification of `enclave` already made, as by
    ///   router discovery, which reported it, kept as the usable one so that
    ///   it isn't repeated.
    /// - Parameter requiresHPKEKey: Whether an attempt fails when the
    ///   verified facts endorse no usable HPKE key, as for EHBP.
    init(
        enclave: String,
        pin: Pin,
        attestationRelay: String?,
        attestor: Attestor,
        initial: VerificationReport? = nil,
        onVerificationAttempt: VerificationCallback? = nil,
        requiresHPKEKey: Bool = false,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.enclave = enclave
        self.pin = pin
        self.attestationRelay = attestationRelay
        self.attestor = attestor
        self.usable = initial
        self.lastVerificationAttempt = initial.map { .success($0) }
        self.onVerificationAttempt = onVerificationAttempt
        self.requiresHPKEKey = requiresHPKEKey
        self.now = now
    }

    /// Stops verifying: later calls fail, and a verification in progress is
    /// cancelled.
    func close() {
        closed = true
        inFlight?.cancel()
    }

    private func checkOpen() throws {
        if closed {
            throw TinfoilError.configuration("the client is closed")
        }
    }

    /// Verifies the enclave against fresh evidence and returns the report.
    /// Calls made while a verification runs share it. Cancelling a call ends
    /// only its own wait; the shared verification still completes.
    ///
    /// A run that fails with `TinfoilError.attestationError` discards the
    /// usable verification, even one that is still fresh, so that the next
    /// `ensureVerified()` verifies again. A run that fails in any other way,
    /// such as with a network error, keeps it.
    func reverify() async throws -> VerificationReport {
        try checkOpen()
        let task: Task<VerificationReport, Error>
        if let inFlight {
            task = inFlight
        } else {
            let replacing = generation
            retried = []
            task = Task {
                let outcome: Result<VerificationReport, Error>
                do {
                    let report = try await self.attestor.attest(
                        host: self.enclave,
                        relay: self.attestationRelay,
                        pin: self.pin,
                        retried: { await self.noteRetried($0) }
                    )
                    // A document without the key that the transport binds to
                    // can't carry requests, so the attempt fails.
                    if self.requiresHPKEKey {
                        _ = try EHBPVerifiedEndpoint.publicKey(hex: report.passedFacts().hpkePublicKey)
                    }
                    outcome = .success(report)
                } catch {
                    outcome = .failure(error)
                }
                let (result, attempts) = self.settle(outcome, replacing: replacing)
                // Reported once per run, however many callers share it, and
                // only after the run is forgotten, so that a callback that
                // verifies again starts a run of its own.
                await Self.report(attempts, host: self.enclave, to: self.onVerificationAttempt)
                return try result.get()
            }
            inFlight = task
        }
        return try await waitForSharedTask(task)
    }

    /// Discards `rejected`, a verification whose key the enclave refused, so
    /// that no later request uses it and `currentVerification` is nil until a
    /// new verification succeeds. A verification that has replaced it since
    /// the request was sent is kept, so that a late rejection can't discard
    /// one that is newer than the key that it refused.
    func discard(_ rejected: VerificationReport) {
        if usable == rejected {
            usable = nil
        }
    }

    /// Records a failed attempt that the run in progress retries.
    private func noteRetried(_ error: TinfoilError) {
        guard !closed else {
            return
        }
        lastVerificationAttempt = .failure(error)
        retried.append(error)
    }

    /// Decides the outcome of the run in progress, forgets the run, and
    /// returns its result and the attempts that it made, in order, for the
    /// callback.
    private func settle(
        _ outcome: Result<VerificationReport, Error>,
        replacing: UInt64
    ) -> (Result<VerificationReport, Error>, [Result<VerificationReport, TinfoilError>]) {
        inFlight = nil
        var attempts = retried.map { Result<VerificationReport, TinfoilError>.failure($0) }
        retried = []
        // A run that the client's close ended isn't a verification, so it
        // isn't kept, used or reported, and a verification that finishes
        // despite a late close is not kept or used.
        guard !closed else {
            if case .success = outcome {
                return (.failure(TinfoilError.configuration("the client is closed")), [])
            }
            return (outcome, [])
        }
        switch outcome {
        case .success(let report):
            usable = report
            generation &+= 1
            lastVerificationAttempt = .success(report)
            attempts.append(.success(report))
        case .failure(let error as TinfoilError):
            // Evidence that fails verification means the enclave may no
            // longer be the one verified, so its keys aren't used again. A
            // verification that became usable since the run started is newer
            // than this evidence, so it is kept.
            if case .attestationError = error, generation == replacing {
                usable = nil
            }
            lastVerificationAttempt = .failure(error)
            attempts.append(.failure(error))
        case .failure:
            // A cancellation has no outcome to report.
            break
        }
        return (outcome, attempts)
    }

    /// Calls callback with each attempt, in order, from a task of its own, so
    /// that the callback runs outside this actor and can call the client
    /// without waiting for it.
    private nonisolated static func report(
        _ attempts: [Result<VerificationReport, TinfoilError>],
        host: String,
        to callback: VerificationCallback?
    ) async {
        guard let callback, !attempts.isEmpty else {
            return
        }
        await Task.detached {
            for attempt in attempts {
                callback(host, attempt)
            }
        }.value
    }

    /// Returns a verification that is valid now, verifying only when there
    /// is none yet or the latest has reached its `freshnessExpiresAt`.
    func ensureVerified() async throws -> VerificationReport {
        try checkOpen()
        if let usable, now() < usable.freshnessExpiresAt {
            return usable
        }
        let verified = try await reverify()
        try checkOpen()
        guard now() < verified.freshnessExpiresAt else {
            throw TinfoilError.attestation("verification of \(enclave) is already past its freshness deadline")
        }
        return verified
    }
}
