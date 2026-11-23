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
    public var pinnedRegisters: VerifiedFacts.Measurement?
    /// The oldest freshness witness accepted, in seconds. Zero selects the
    /// seven-day default; a negative age is refused, and a positive age must
    /// be at least one nanosecond once rounded to whole nanoseconds.
    public var freshnessMaxAge: TimeInterval
    /// Who vouches for the runtime and platform artifacts; artifacts that
    /// Tinfoil's public keys endorse by default
    public var artifacts: ArtifactTrust

    public init(
        pinnedRegisters: VerifiedFacts.Measurement? = nil,
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
            embeddedPlatform: policy.artifacts.platform,
            embeddedArtifacts: policy.artifacts.isEmbedded
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

/// The policy part of the options that the framework's verifier takes as
/// JSON; nil members are left out, which keeps their defaults. Data encodes
/// as standard base64.
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
    /// Whether the artifacts are embedded rather than endorsed
    var embeddedArtifacts = false

    /// The framework's options JSON for this policy and the config trust that
    /// `trust` selects: an object with an optional `config_trust` and an
    /// optional `policy`, each tagged by `type` where it has variants. A
    /// config authorizer is the config trust itself, passed to the framework
    /// beside the JSON, which is then the policy object alone.
    func json(trust: Trust?) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        if case .authorizedBy = trust?.kind {
            return String(decoding: try encoder.encode(policyJSON), as: UTF8.self)
        }
        let options = OptionsJSON(configTrust: trust.flatMap(Self.configTrust), policy: policyJSON)
        return String(decoding: try encoder.encode(options), as: UTF8.self)
    }

    /// The `config_trust` member for `trust`, or nil for the default, Tinfoil's
    /// public registry
    private static func configTrust(_ trust: Trust) -> ConfigTrustJSON? {
        switch trust.kind {
        case let .project(_, registryIDs?):
            return ConfigTrustJSON(type: "registries", ids: registryIDs)
        case let .signedBy(keys, _):
            return ConfigTrustJSON(type: "signing_keys", keysPEM: keys)
        case let .embeddedConfig(bytes, name):
            return ConfigTrustJSON(type: "embedded_config", name: name.isEmpty ? nil : name, bytes: bytes)
        case .repo, .project, .authorizedBy, .either:
            return nil
        }
    }

    private var policyJSON: PolicyJSON {
        var artifacts: ArtifactsJSON?
        if embeddedArtifacts {
            artifacts = ArtifactsJSON(type: "embedded", runtime: embeddedRuntime, platform: embeddedPlatform, freshnessKeysPEM: freshnessSigningKeysPEM)
        } else if let freshnessSigningKeysPEM {
            artifacts = ArtifactsJSON(type: "endorsed", freshnessKeysPEM: freshnessSigningKeysPEM)
        }
        return PolicyJSON(pinnedRegisters: pinnedRegisters, freshnessMaxAgeNs: freshnessMaxAgeNs, artifacts: artifacts)
    }

    private struct OptionsJSON: Encodable {
        let configTrust: ConfigTrustJSON?
        let policy: PolicyJSON

        private enum CodingKeys: String, CodingKey {
            case configTrust = "config_trust"
            case policy
        }
    }

    /// One of the tagged config trust objects; only the members of its type
    /// are set.
    private struct ConfigTrustJSON: Encodable {
        let type: String
        var ids: [String]?
        var keysPEM: [String]?
        var name: String?
        var bytes: Data?

        private enum CodingKeys: String, CodingKey {
            case type, ids, name, bytes
            case keysPEM = "keys_pem"
        }
    }

    private struct PolicyJSON: Encodable {
        let pinnedRegisters: Measurement?
        let freshnessMaxAgeNs: Int64?
        let artifacts: ArtifactsJSON?

        private enum CodingKeys: String, CodingKey {
            case pinnedRegisters = "pinned_registers"
            case freshnessMaxAgeNs = "freshness_max_age_ns"
            case artifacts
        }
    }

    /// One of the tagged artifact trust objects; only the members of its type
    /// are set.
    private struct ArtifactsJSON: Encodable {
        let type: String
        var runtime: Data?
        var platform: Data?
        var freshnessKeysPEM: [String]?

        private enum CodingKeys: String, CodingKey {
            case type, runtime, platform
            case freshnessKeysPEM = "freshness_keys_pem"
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
