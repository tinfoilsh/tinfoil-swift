import Foundation
import TinfoilGo

/// The verification policy that attestation documents are appraised under,
/// on top of the trust that a client verifies its enclave under. Every client
/// takes one; without it, a client uses the defaults: Tinfoil's signing keys
/// and a seven-day freshness bound.
///
/// The initializer checks the options and throws
/// `TinfoilError.configurationError` for an invalid one, so that a client
/// never starts with a policy that can't verify. A verifier is immutable and
/// safe to share between clients.
public final class Verifier: Sendable {
    /// The framework's options for this policy, without a config trust
    private let options: VerifierOptions

    /// - Parameters:
    ///   - pinnedRegisters: Register values the enclave measurement must also
    ///     match. An empty register keeps its default check.
    ///   - freshnessMaxAge: Oldest freshness witness accepted, in seconds.
    ///     Nil keeps the seven-day default; a value must be at least one
    ///     nanosecond once rounded to whole nanoseconds.
    ///   - freshnessSigningKeys: PEM `PUBLIC KEY` blocks for Tinfoil's runtime
    ///     and platform approvals, replacing the built-in keys. Must not be
    ///     empty.
    ///   - embeddedReferences: Caller-trusted components that replace their
    ///     endorsements. Set at least one component.
    public init(
        pinnedRegisters: Verification.Measurement? = nil,
        freshnessMaxAge: TimeInterval? = nil,
        freshnessSigningKeys: [String]? = nil,
        embeddedReferences: EmbeddedReferences? = nil
    ) throws {
        if let embeddedReferences, embeddedReferences.runtime == nil, embeddedReferences.platform == nil {
            throw TinfoilError.configuration("embedded references must contain at least one component")
        }
        options = VerifierOptions(
            pinnedRegisters: pinnedRegisters.map { .init(type: $0.type, registers: $0.registers) },
            freshnessMaxAgeNs: try freshnessMaxAge.map(Self.nanoseconds),
            freshnessSigningKeysPEM: freshnessSigningKeys,
            embeddedRuntime: embeddedReferences?.runtime,
            embeddedPlatform: embeddedReferences?.platform
        )
        // Building a verifier checks the policy now rather than in a client.
        _ = try backend(trust: nil)
    }

    /// The framework verifier for `trust` under this policy; nil selects the
    /// default config trust, Tinfoil's public registry.
    func backend(trust: Trust?) throws -> GoAttestationVerifier {
        try GoAttestationVerifier(trust: trust, policy: options)
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
}

/// The policy part of the options JSON that the framework's verifier takes;
/// nil members are left out, which keeps their defaults. Data encodes as
/// standard base64.
struct VerifierOptions: Sendable {
    struct Measurement: Encodable, Sendable {
        let type: String
        let registers: [String]
    }

    var pinnedRegisters: Measurement?
    var freshnessMaxAgeNs: Int64?
    var freshnessSigningKeysPEM: [String]?
    var embeddedRuntime: Data?
    var embeddedPlatform: Data?

    static let defaults = VerifierOptions()

    /// The framework's options JSON for this policy and the config trust that
    /// `trust` selects. A config authorizer is not part of the JSON: it is
    /// passed to the framework beside it.
    func json(trust: Trust?) throws -> String {
        var encoded = Encoded(policy: self)
        switch trust?.kind {
        case let .project(_, registryIDs?):
            encoded.configRegistryIDs = registryIDs
        case let .signedBy(keys, _):
            encoded.configSigningKeysPEM = keys
        case let .embeddedConfig(bytes, name):
            encoded.embeddedConfig = .init(name: name.isEmpty ? nil : name, bytes: bytes)
        case nil, .repo, .project, .authorizedBy, .either:
            break
        }
        return String(decoding: try JSONEncoder().encode(encoded), as: UTF8.self)
    }

    private struct Encoded: Encodable {
        struct EmbeddedConfig: Encodable {
            let name: String?
            let bytes: Data
        }

        let pinnedRegisters: Measurement?
        let freshnessMaxAgeNs: Int64?
        var configRegistryIDs: [String]?
        var configSigningKeysPEM: [String]?
        let freshnessSigningKeysPEM: [String]?
        var embeddedConfig: EmbeddedConfig?
        let embeddedRuntime: Data?
        let embeddedPlatform: Data?

        init(policy: VerifierOptions) {
            pinnedRegisters = policy.pinnedRegisters
            freshnessMaxAgeNs = policy.freshnessMaxAgeNs
            freshnessSigningKeysPEM = policy.freshnessSigningKeysPEM
            embeddedRuntime = policy.embeddedRuntime
            embeddedPlatform = policy.embeddedPlatform
        }

        private enum CodingKeys: String, CodingKey {
            case pinnedRegisters = "pinned_registers"
            case freshnessMaxAgeNs = "freshness_max_age_ns"
            case configRegistryIDs = "config_registry_ids"
            case configSigningKeysPEM = "config_signing_keys_pem"
            case freshnessSigningKeysPEM = "freshness_signing_keys_pem"
            case embeddedConfig = "embedded_config"
            case embeddedRuntime = "embedded_runtime"
            case embeddedPlatform = "embedded_platform"
        }
    }
}

/// Decides whether a deployment's config is authorized, in place of verifying
/// its endorsement. Throw to reject it: the document then fails verification
/// with `TinfoilError.attestationError` at the provenance layer, carrying the
/// error's description. Return to authorize it; the runtime, platform and
/// hardware are still verified, but approving a config authenticates no
/// registry, name or approval time.
///
/// It runs synchronously during verification, possibly on several threads at
/// once, so it must be thread-safe and fast.
public typealias ConfigAuthorizer = @Sendable (ConfigEndorsement) throws -> Void

/// A deployment's config material, as the attestation document carries it.
/// It is untrusted: a `ConfigAuthorizer` decides whether to accept it.
public struct ConfigEndorsement: Sendable, Equatable {
    /// The config's bytes
    public let config: Data
    /// The endorsement's `sha256:<hex>` reference; empty for a plain config
    public let reference: String
    /// The endorsement's Sigstore bundle, the exact JSON bytes from the
    /// document; empty for a plain config
    public let sigstoreBundle: Data
    /// The registry's issuer certificate, DER; empty unless certified
    public let issuerCertificate: Data
}

extension ConfigEndorsement {
    /// Decodes the framework's payload, in which every byte string is
    /// standard base64 and an absent member is empty.
    init(payload: String) throws {
        struct Payload: Decodable {
            let config: String
            let reference: String?
            let sigstoreBundle: String?
            let issuerCertificateDER: String?

            private enum CodingKeys: String, CodingKey {
                case config, reference
                case sigstoreBundle = "sigstore_bundle"
                case issuerCertificateDER = "issuer_certificate_der"
            }
        }
        func bytes(_ value: String?, _ field: String) throws -> Data {
            guard let value else { return Data() }
            guard let data = Data(base64Encoded: value) else {
                throw TinfoilError.attestation("config endorsement has an invalid \(field)")
            }
            return data
        }
        let decoded: Payload
        do {
            decoded = try JSONDecoder().decode(Payload.self, from: Data(payload.utf8))
        } catch {
            throw TinfoilError.attestation("unreadable config endorsement: \(error.localizedDescription)")
        }
        self.init(
            config: try bytes(decoded.config, "config"),
            reference: decoded.reference ?? "",
            sigstoreBundle: try bytes(decoded.sigstoreBundle, "sigstore_bundle"),
            issuerCertificate: try bytes(decoded.issuerCertificateDER, "issuer_certificate_der")
        )
    }
}

/// Hands each config the framework asks about to a `ConfigAuthorizer`, and
/// its rejection back as an error whose description the framework keeps.
final class ConfigAuthorizerBridge: NSObject, MobileConfigAuthorizerProtocol, Sendable {
    private let authorize: ConfigAuthorizer

    init(_ authorize: @escaping ConfigAuthorizer) {
        self.authorize = authorize
    }

    func authorizeConfig(_ endorsementJSON: String?) throws {
        do {
            try authorize(ConfigEndorsement(payload: endorsementJSON ?? ""))
        } catch {
            throw NSError(
                domain: "sh.tinfoil.config-authorizer",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: error.localizedDescription]
            )
        }
    }
}

/// Caller-trusted runtime and platform artifacts that replace their
/// endorsements. Only the artifacts that are set are replaced; the hardware is
/// always verified, and so are the bindings between components and any pinned
/// registers. Set at least one.
public struct EmbeddedReferences: Sendable, Equatable {
    /// The runtime manifest that the config pins
    public var runtime: Data?
    /// A platform policy artifact (platform-endorsements/v2)
    public var platform: Data?

    public init(runtime: Data? = nil, platform: Data? = nil) {
        self.runtime = runtime
        self.platform = platform
    }
}
