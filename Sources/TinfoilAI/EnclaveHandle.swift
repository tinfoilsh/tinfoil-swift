import Foundation

/// A handle on one attested enclave, matching tinfoil-go's `enclave.Handle`.
/// Pass one to `TinfoilAI.create` to configure how the client's enclave is
/// verified.
///
/// Each `verify()` is one run. A run fetches an enclave's attestation document
/// and has tinfoil-go verify it, retrying a failed attempt once. Before the
/// first run picks an enclave, it may try several of Tinfoil's routers. Every
/// enclave whose evidence verifies is passed to `onEnclaveVerified`, which can
/// reject it, and the run's final result goes to `onVerificationResult`. The
/// latest successful result stays in `verification`.
public actor EnclaveHandle {
    private let enclave: String?
    private let repo: String
    private let attestationRelay: String?
    private let attestor: Attestor
    private let onVerificationResult: VerificationResultCallback?
    /// The configured enclave, or the router discovery picked on the first
    /// verification; later verifications stay with it.
    private var selectedEnclave: String?
    /// The verification in progress, shared by every caller that asks while
    /// it runs
    private var inFlight: Task<Verification, Error>?

    /// The latest successful verification, or nil before the first
    public private(set) var verification: Verification?

    /// - Parameters:
    ///   - enclave: Host of the enclave to verify, such as
    ///     "inference.tinfoil.sh". When nil, the first verification picks one
    ///     of Tinfoil's routers, which requires the default repo.
    ///   - repo: The trusted owner/name[@tag][@sha256:digest] the enclave's
    ///     code must come from.
    ///   - attestationRelay: Host, with an optional port, that forwards
    ///     attestation requests to the enclave. Without an enclave, a relay is
    ///     asked for the fallback router rather than running discovery.
    ///   - policy: Checks beyond the defaults.
    ///   - onEnclaveVerified: Called each time an enclave's evidence verifies,
    ///     before it is used; throw to reject the enclave. This callback can
    ///     be used to define additional user-specific policies that further
    ///     restrict which enclaves are accepted.
    ///   - onVerificationResult: Called with each `verify()` run's final result
    ///     (i.e. after potentially several enclaves are tried); this callback
    ///     only observes the end verification result and cannot synchronously
    ///     reject enclaves.
    public init(
        enclave: String? = nil,
        repo: String = TinfoilConstants.defaultGithubRepo,
        attestationRelay: String? = nil,
        policy: VerificationPolicy = VerificationPolicy(),
        onEnclaveVerified: EnclaveVerifiedCallback? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) throws {
        try self.init(
            enclave: enclave,
            repo: repo,
            attestationRelay: attestationRelay,
            attestor: Attestor(verifier: GoAttestationVerifier(policy: policy), onEnclaveVerified: onEnclaveVerified),
            onVerificationResult: onVerificationResult
        )
    }

    init(
        enclave: String?,
        repo: String,
        attestationRelay: String?,
        attestor: Attestor,
        onVerificationResult: VerificationResultCallback? = nil
    ) throws {
        guard enclave != nil || repo == TinfoilConstants.defaultGithubRepo else {
            throw TinfoilError.invalidConfiguration(
                "an enclave is required to verify against \(repo); only Tinfoil's routers are discovered"
            )
        }
        self.enclave = enclave
        self.repo = repo
        self.attestationRelay = attestationRelay
        self.attestor = attestor
        self.onVerificationResult = onVerificationResult
    }

    /// Verifies the enclave against fresh evidence and returns the result.
    /// Calls made while a verification runs share it, so concurrent first
    /// calls discover a single router. Cancelling a call ends only its own
    /// wait; the shared verification still completes.
    public func verify() async throws -> Verification {
        let task: Task<Verification, Error>
        if let inFlight {
            task = inFlight
        } else {
            task = Task {
                defer { self.inFlight = nil }
                // Reported here, once per run, however many callers share it.
                do {
                    let verified = try await self.verifyNow()
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

    private func verifyNow() async throws -> Verification {
        let verified: Verification
        if let host = selectedEnclave ?? enclave {
            verified = try await attestor.attest(host: host, relay: attestationRelay, repo: repo)
        } else if let attestationRelay {
            verified = try await attestor.attest(
                host: TinfoilConstants.fallbackEnclave,
                relay: attestationRelay,
                repo: repo
            )
        } else {
            verified = try await attestor.attestDefaultRouter()
        }
        selectedEnclave = verified.enclaveHost
        verification = verified
        return verified
    }
}
