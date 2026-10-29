import Foundation

/// One attested enclave's verification state: it verifies the enclave and
/// keeps the result until it expires or the caller asks for a fresh one. It
/// sends no requests; `EnclaveConnection` ties traffic to the keys it
/// verifies.
///
/// Each `reverify()` is one run. A run fetches the enclave's attestation
/// document and has the TinfoilGo verifier check it, retrying a failed
/// attempt once. The run's result goes to `onVerificationResult`.
actor EnclaveHandle {
    nonisolated let enclave: String
    nonisolated let repo: String
    private let attestationRelay: String?
    private let attestor: Attestor
    private let onVerificationResult: VerificationResultCallback?
    private let now: @Sendable () -> Date
    /// The verification in progress, shared by every caller that asks while
    /// it runs
    private var inFlight: Task<Verification, Error>?

    /// The latest successful verification, or nil before the first. It may
    /// have expired; `ensureVerified()` returns one that has not.
    private(set) var current: Verification?

    /// - Parameter initial: A verification of `enclave` already made, as by
    ///   router discovery, kept as the current one so it isn't repeated.
    init(
        enclave: String,
        repo: String,
        attestationRelay: String?,
        attestor: Attestor,
        initial: Verification? = nil,
        onVerificationResult: VerificationResultCallback? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.enclave = enclave
        self.repo = repo
        self.attestationRelay = attestationRelay
        self.attestor = attestor
        self.current = initial
        self.onVerificationResult = onVerificationResult
        self.now = now
    }

    /// Verifies the enclave against fresh evidence and returns the result.
    /// Calls made while a verification runs share it. Cancelling a call ends
    /// only its own wait; the shared verification still completes.
    func reverify() async throws -> Verification {
        let task: Task<Verification, Error>
        if let inFlight {
            task = inFlight
        } else {
            task = Task {
                defer { self.inFlight = nil }
                // Reported here, once per run, however many callers share it.
                do {
                    let verified = try await self.attestor.attest(
                        host: self.enclave,
                        relay: self.attestationRelay,
                        repo: self.repo
                    )
                    self.current = verified
                    self.onVerificationResult?(.success(verified))
                    return verified
                } catch let error as TinfoilError {
                    self.onVerificationResult?(.failure(error))
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
        if let current, now() < current.freshnessExpiresAt {
            return current
        }
        let verified = try await reverify()
        guard now() < verified.freshnessExpiresAt else {
            throw TinfoilError.attestation("verification of \(enclave) is already past its freshness deadline")
        }
        return verified
    }
}
