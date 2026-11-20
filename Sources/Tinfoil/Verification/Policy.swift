import Foundation
import TinfoilGo

/// The verification policy that attestation documents are appraised under,
/// on top of the trust that a client verifies its enclave under. It is plain
/// data: a client builds its verifier from it, and checks it before any
/// network I/O, throwing `TinfoilError.configurationError` for an invalid
/// value. The default policy keeps every default: no register pins, the
/// seven-day freshness bound, and runtime and platform artifacts that
/// Tinfoil's public keys endorse.
public struct Policy: Sendable, Equatable {
    /// Register values that the enclave measurement must also match. An empty
    /// register keeps its default check. Pins for one platform reject every
    /// enclave on the other.
    public var pinnedRegisters: Verification.Measurement?
    /// The oldest freshness witness accepted, in seconds. Zero selects the
    /// seven-day default; a negative age is refused, and so is a positive one
    /// under a nanosecond, which the verifier would read as zero.
    public var freshnessMaxAge: TimeInterval
    /// Who vouches for the runtime and platform artifacts; artifacts that
    /// Tinfoil's public keys endorse by default
    public var artifacts: ArtifactTrust

    public init(
        pinnedRegisters: Verification.Measurement? = nil,
        freshnessMaxAge: TimeInterval = 0,
        artifacts: ArtifactTrust = .endorsed()
    ) {
        self.pinnedRegisters = pinnedRegisters
        self.freshnessMaxAge = freshnessMaxAge
        self.artifacts = artifacts
    }
}

/// Who vouches for the runtime and platform artifacts that an enclave runs:
/// `.endorsed(freshnessKeys:)`, the default, or
/// `.embedded(runtime:platform:freshnessKeys:)`.
public struct ArtifactTrust: Sendable, Equatable {
    /// The caller's runtime manifest, which replaces its endorsement
    public let runtime: Data?
    /// The caller's platform policy artifact (platform-endorsements/v2),
    /// which replaces its endorsement
    public let platform: Data?
    /// PEM `PUBLIC KEY` blocks that replace Tinfoil's public keys for the
    /// artifacts that are endorsed; nil keeps Tinfoil's keys
    public let freshnessKeys: [String]?

    /// Accepts the artifacts that Tinfoil endorses.
    ///
    /// - Parameter freshnessKeys: PEM `PUBLIC KEY` blocks that replace
    ///   Tinfoil's public keys; nil keeps them, and an empty list is refused.
    public static func endorsed(freshnessKeys: [String]? = nil) -> ArtifactTrust {
        ArtifactTrust(runtime: nil, platform: nil, freshnessKeys: freshnessKeys)
    }

    /// Accepts the caller's own artifacts in place of their endorsements, and
    /// the endorsed one for an artifact that the caller doesn't supply. The
    /// hardware is always verified, and so are the bindings between
    /// components and any pinned registers. Set at least one of `runtime` and
    /// `platform`.
    ///
    /// - Parameter freshnessKeys: PEM `PUBLIC KEY` blocks that replace
    ///   Tinfoil's public keys for an artifact that the caller doesn't
    ///   supply; nil keeps them. An empty list is refused, and so is a list
    ///   with both artifacts embedded, since nothing would be left for the
    ///   keys to verify.
    public static func embedded(runtime: Data? = nil, platform: Data? = nil, freshnessKeys: [String]? = nil) -> ArtifactTrust {
        ArtifactTrust(runtime: runtime, platform: platform, freshnessKeys: freshnessKeys, isEmbedded: true)
    }

    /// Whether the artifacts are embedded rather than endorsed
    let isEmbedded: Bool

    private init(runtime: Data?, platform: Data?, freshnessKeys: [String]?, isEmbedded: Bool = false) {
        self.runtime = runtime
        self.platform = platform
        self.freshnessKeys = freshnessKeys
        self.isEmbedded = isEmbedded
    }
}

extension VerifierOptions {
    /// The framework's options for `policy`, after checking what the
    /// framework would read differently from what the caller meant.
    init(policy: Policy) throws {
        if policy.artifacts.isEmbedded, policy.artifacts.runtime == nil, policy.artifacts.platform == nil {
            throw TinfoilError.configuration("embedded artifacts must contain a runtime or a platform")
        }
        self.init(
            pinnedRegisters: policy.pinnedRegisters.map { .init(type: $0.type, registers: $0.registers) },
            freshnessMaxAgeNs: try Self.nanoseconds(policy.freshnessMaxAge),
            freshnessSigningKeysPEM: policy.artifacts.freshnessKeys,
            embeddedRuntime: policy.artifacts.runtime,
            embeddedPlatform: policy.artifacts.platform
        )
    }

    /// The framework takes the age as an integer count of nanoseconds, and
    /// reads zero as "keep the default", which an age of zero asks for. So a
    /// positive age must be at least one nanosecond once rounded: one under
    /// half a nanosecond would otherwise silently select the seven-day
    /// default. A negative age, or one with no such count, such as NaN,
    /// infinity or more than about 292 years, is refused rather than trapping
    /// in the conversion.
    private static func nanoseconds(_ seconds: TimeInterval) throws -> Int64? {
        if seconds == 0 {
            return nil
        }
        guard let nanoseconds = Int64(exactly: (seconds * 1_000_000_000).rounded()), nanoseconds > 0 else {
            throw TinfoilError.configuration(
                "freshness maximum age must be zero, for the default, or a positive, finite number of seconds of at least a nanosecond, not \(seconds)"
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
