import Foundation

/// Verifies an enclave's attestation. The SDK fetches each attestation
/// document itself and tinfoil-go verifies it; every `verify()` checks fresh
/// evidence, and the latest successful result stays in `verification`.
public actor SecureClient {
    private let enclave: String?
    private let repo: String
    private let attestationRelay: String?
    private let attestor: Attestor
    /// The configured enclave, or the router discovery picked on the first
    /// verification; later verifications stay with it.
    private var selectedEnclave: String?

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
    public init(
        enclave: String? = nil,
        repo: String = TinfoilConstants.defaultGithubRepo,
        attestationRelay: String? = nil,
        policy: VerificationPolicy = VerificationPolicy()
    ) throws {
        try self.init(
            enclave: enclave,
            repo: repo,
            attestationRelay: attestationRelay,
            attestor: Attestor(verifier: GoAttestationVerifier(policy: policy))
        )
    }

    init(enclave: String?, repo: String, attestationRelay: String?, attestor: Attestor) throws {
        guard enclave != nil || repo == TinfoilConstants.defaultGithubRepo else {
            throw TinfoilError.invalidConfiguration(
                "an enclave is required to verify against \(repo); only Tinfoil's routers are discovered"
            )
        }
        self.enclave = enclave
        self.repo = repo
        self.attestationRelay = attestationRelay
        self.attestor = attestor
    }

    /// Verifies the enclave against fresh evidence and returns the result.
    public func verify() async throws -> Verification {
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
