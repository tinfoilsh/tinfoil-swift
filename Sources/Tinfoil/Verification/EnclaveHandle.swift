import Foundation

/// One attested enclave's verification state: it verifies the enclave and
/// keeps the result until it expires or the caller asks for a fresh one. It
/// sends no requests; `EnclaveConnection` ties traffic to the keys it
/// verifies.
///
/// Each `reverify()` is one run. A run fetches the enclave's attestation
/// document and has the TinfoilGo verifier check it, retrying a failed
/// attempt once. The run's result goes to `onVerificationResult`. A run
/// that fails attestation withdraws the verification that it was replacing
/// from `usable`, so that no later request uses it; `current` keeps it.
actor EnclaveHandle {
    nonisolated let enclave: String
    nonisolated let pin: Pin
    private let attestationRelay: String?
    private let attestor: Attestor
    private let onVerificationResult: VerificationResultCallback?
    private let now: @Sendable () -> Date
    /// The verification in progress, shared by every caller that asks while
    /// it runs
    private var inFlight: Task<Verification, Error>?
    private var closed = false

    /// The latest successful verification, or nil before the first. It may
    /// have expired or been discarded, and a failed run doesn't change it;
    /// `ensureVerified()` returns one that is valid now. Requests never use
    /// it: they take `usable`.
    private(set) var current: Verification?
    /// The verification that requests may use: `current`, or nil before the
    /// first and after a run that fails attestation discards it. It may have
    /// expired; `ensureVerified()` returns one that has not.
    private(set) var usable: Verification?
    /// Counts the verifications that have become `usable`, so that a failed
    /// run discards only the one that it was replacing
    private var generation: UInt64 = 0

    /// - Parameter initial: A verification of `enclave` already made, as by
    ///   router discovery, kept as the current one so it isn't repeated.
    init(
        enclave: String,
        pin: Pin,
        attestationRelay: String?,
        attestor: Attestor,
        initial: Verification? = nil,
        onVerificationResult: VerificationResultCallback? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.enclave = enclave
        self.pin = pin
        self.attestationRelay = attestationRelay
        self.attestor = attestor
        self.current = initial
        self.usable = initial
        self.onVerificationResult = onVerificationResult
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

    /// Verifies the enclave against fresh evidence and returns the result.
    /// Calls made while a verification runs share it. Cancelling a call ends
    /// only its own wait; the shared verification still completes.
    ///
    /// A run that fails with `TinfoilError.attestationError` discards the
    /// usable verification, even one that is still fresh, so that the next
    /// `ensureVerified()` verifies again; `current` still returns it. A run
    /// that fails in any other way, such as with a network error, keeps it.
    func reverify() async throws -> Verification {
        try checkOpen()
        let task: Task<Verification, Error>
        if let inFlight {
            task = inFlight
        } else {
            let replacing = generation
            task = Task {
                defer { self.inFlight = nil }
                // Reported here, once per run, however many callers share it.
                do {
                    let verified = try await self.attestor.attest(
                        host: self.enclave,
                        relay: self.attestationRelay,
                        pin: self.pin
                    )
                    // A verification that finishes despite a late close is
                    // not kept or used.
                    try self.checkOpen()
                    self.current = verified
                    self.usable = verified
                    self.generation &+= 1
                    self.onVerificationResult?(.success(verified))
                    return verified
                } catch let error as TinfoilError {
                    // Evidence that fails verification means the enclave may
                    // no longer be the one verified, so its keys aren't used
                    // again. A verification that became usable since the run
                    // started is newer than this evidence, so it is kept, and
                    // a run that the client's close ended changes nothing.
                    if case .attestationError = error, self.generation == replacing, !self.closed {
                        self.usable = nil
                    }
                    // A run that the client's close ended isn't a failed
                    // verification, so it isn't reported as one.
                    if !self.closed {
                        self.onVerificationResult?(.failure(error))
                    }
                    throw error
                }
            }
            inFlight = task
        }
        return try await waitForSharedTask(task)
    }

    /// Returns a verification that is valid now, verifying only when there
    /// is none yet or the latest has reached its `freshnessExpiresAt`.
    func ensureVerified() async throws -> Verification {
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
