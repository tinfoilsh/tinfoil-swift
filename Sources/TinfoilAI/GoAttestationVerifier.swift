import Foundation
import Tinfoil

/// Verification policy beyond the defaults, as tinfoil-go's options JSON
/// carries it.
struct VerificationPolicy: Equatable, Sendable {
    /// Register values the enclave measurement must also match. An empty
    /// register keeps its default check.
    var pinnedRegisters: Verification.Measurement?
    /// Oldest freshness witness accepted. Nil keeps the seven-day default.
    var freshnessMaxAge: TimeInterval?

    /// The options JSON `MobileNewVerifier` takes; empty for the defaults.
    /// Out-of-range values are left for Go to reject.
    func optionsJSON() throws -> String {
        guard pinnedRegisters != nil || freshnessMaxAge != nil else {
            return ""
        }
        let options = Options(
            pinnedRegisters: pinnedRegisters.map { .init(type: $0.type, registers: $0.registers) },
            freshnessMaxAgeNs: freshnessMaxAge.map { Int64(($0 * 1_000_000_000).rounded()) }
        )
        return String(decoding: try JSONEncoder().encode(options), as: UTF8.self)
    }

    private struct Options: Encodable {
        struct Measurement: Encodable {
            let type: String
            let registers: [String]
        }

        let pinnedRegisters: Measurement?
        let freshnessMaxAgeNs: Int64?

        private enum CodingKeys: String, CodingKey {
            case pinnedRegisters = "pinned_registers"
            case freshnessMaxAgeNs = "freshness_max_age_ns"
        }
    }
}

/// The tinfoil-go verifier bound through gomobile. Go makes every trust
/// decision; this only translates types and errors across the FFI.
final class GoAttestationVerifier: AttestationVerifier, @unchecked Sendable {
    // MobileVerifier wraps an immutable Go policy that is safe to use from
    // several threads at once.
    private let verifier: MobileVerifier

    init(policy: VerificationPolicy = VerificationPolicy()) throws {
        var error: NSError?
        let verifier = MobileNewVerifier(try policy.optionsJSON(), &error)
        if let error {
            throw Self.classify(error)
        }
        guard let verifier else {
            throw TinfoilError.invalidConfiguration("tinfoil-go returned no verifier")
        }
        self.verifier = verifier
    }

    func newNonce() -> Data {
        // Go never returns nil here. If it did, the empty nonce would be
        // refused by attestationURL, so the attempt still fails closed.
        MobileNewNonce() ?? Data()
    }

    func attestationURL(host: String, relay: String?, nonce: Data) throws -> URL {
        var error: NSError?
        let url = MobileAttestationURL(host, relay ?? "", nonce, &error)
        if let error {
            throw Self.classify(error)
        }
        guard let parsed = URL(string: url) else {
            throw TinfoilError.invalidConfiguration("tinfoil-go returned an invalid attestation URL: \(url)")
        }
        return parsed
    }

    func verify(document: Data, nonce: Data, repo: String, enclaveHost: String) throws -> Verification {
        var error: NSError?
        let payload = verifier.verify(document, nonce: nonce, repo: repo, error: &error)
        if let error {
            throw Self.classify(error)
        }
        return try Verification(payload: payload, enclaveHost: enclaveHost)
    }

    private static func classify(_ error: Error) -> TinfoilError {
        TinfoilError.fromVerifier(
            error,
            configurationPrefix: MobileConfigurationErrorPrefix,
            attestationPrefix: MobileAttestationErrorPrefix
        )
    }
}
