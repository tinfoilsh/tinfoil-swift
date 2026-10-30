import Foundation
import TinfoilGo

extension VerificationPolicy {
    /// The options JSON `MobileNewVerifier` takes; empty for the defaults.
    /// The framework validates the rest, such as the shape of pinned
    /// registers.
    func optionsJSON() throws -> String {
        guard pinnedRegisters != nil || freshnessMaxAge != nil else {
            return ""
        }
        let options = Options(
            pinnedRegisters: pinnedRegisters.map { .init(type: $0.type, registers: $0.registers) },
            freshnessMaxAgeNs: try freshnessMaxAge.map(Self.nanoseconds)
        )
        return String(decoding: try JSONEncoder().encode(options), as: UTF8.self)
    }

    /// The framework takes the age as an integer count of nanoseconds, and
    /// reads zero as "keep the default". So an age must be at least one
    /// nanosecond once rounded: 0, or a positive age under half a nanosecond,
    /// would otherwise silently select the seven-day default, and nil is the
    /// way to ask for it. A value with no such count, such as NaN, infinity or
    /// more than about 292 years, is refused rather than trapping in the
    /// conversion.
    private static func nanoseconds(_ seconds: TimeInterval) throws -> Int64 {
        guard let nanoseconds = Int64(exactly: (seconds * 1_000_000_000).rounded()), nanoseconds > 0 else {
            throw TinfoilError.configuration(
                "freshness maximum age must be a positive, finite number of seconds of at least a nanosecond, not \(seconds)"
            )
        }
        return nanoseconds
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

/// The TinfoilGo framework's verifier. It makes every trust decision; this
/// only translates types and errors across the framework boundary.
final class GoAttestationVerifier: AttestationVerifier, @unchecked Sendable {
    // MobileVerifier wraps an immutable policy that is safe to use from
    // several threads at once.
    private let verifier: MobileVerifier

    init(policy: VerificationPolicy = VerificationPolicy()) throws {
        var error: NSError?
        let verifier = MobileNewVerifier(try policy.optionsJSON(), &error)
        if let error {
            throw Self.classify(error)
        }
        guard let verifier else {
            throw TinfoilError.configuration("TinfoilGo returned no verifier")
        }
        self.verifier = verifier
    }

    func newNonce() -> Data {
        // The framework never returns nil here. If it did, the empty nonce
        // would be refused by attestationURL, so the attempt still fails
        // closed.
        MobileNewNonce() ?? Data()
    }

    func attestationURL(host: String, relay: String?, nonce: Data) throws -> URL {
        var error: NSError?
        let url = MobileAttestationURL(host, relay ?? "", nonce, &error)
        if let error {
            throw Self.classify(error)
        }
        guard let parsed = URL(string: url) else {
            throw TinfoilError.configuration("TinfoilGo returned an invalid attestation URL: \(url)")
        }
        return parsed
    }

    func verify(document: Data, nonce: Data, repo: String) throws -> Verification {
        var error: NSError?
        let payload = verifier.verify(document, nonce: nonce, repo: repo, error: &error)
        if let error {
            throw Self.classify(error)
        }
        return try Verification(payload: payload)
    }

    private static func classify(_ error: Error) -> TinfoilError {
        TinfoilError.fromVerifier(
            error,
            usagePrefix: MobileUsageErrorPrefix,
            verificationPrefix: MobileVerificationErrorPrefix
        )
    }
}
