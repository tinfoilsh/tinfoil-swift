import Foundation
import TinfoilGo

/// The trust policy that attestation documents are appraised under. Every
/// client takes one; without it, a client uses the defaults: Tinfoil's public
/// config registry, Tinfoil's signing keys and a seven-day freshness bound.
///
/// The initializer checks the options, including the conflicts between trust
/// sources, and throws `TinfoilError.configurationError` for an invalid
/// combination, so a client never starts with a policy that can't verify.
/// A verifier is immutable and safe to share between clients.
public final class Verifier: Sendable {
    /// Tinfoil's public config registry. To accept configs from a private
    /// registry as well as public ones, list both in `configRegistryIDs`.
    public static let publicRegistryID: String = MobilePublicRegistryID

    /// The framework verifier that clients built with this policy use
    let backend: GoAttestationVerifier

    /// - Parameters:
    ///   - pinnedRegisters: Register values the enclave measurement must also
    ///     match. An empty register keeps its default check.
    ///   - freshnessMaxAge: Oldest freshness witness accepted, in seconds.
    ///     Nil keeps the seven-day default; a value must be at least one
    ///     nanosecond once rounded to whole nanoseconds.
    ///   - configRegistryIDs: The config registries accepted, replacing the
    ///     public registry. Must not be empty.
    ///   - configSigningKeys: PEM `PUBLIC KEY` blocks that config approvals
    ///     must be signed with, replacing registry trust. Must not be empty.
    ///   - freshnessSigningKeys: PEM `PUBLIC KEY` blocks for Tinfoil's runtime
    ///     and platform approvals, replacing the built-in keys. Must not be
    ///     empty.
    ///   - embeddedReferences: Caller-trusted components that replace their
    ///     endorsements. Set at least one component.
    ///   - configAuthorizer: Decides which configs are authorized, replacing
    ///     their endorsements. A client with one needs an explicit enclave and
    ///     a nil repo.
    public init(
        pinnedRegisters: Verification.Measurement? = nil,
        freshnessMaxAge: TimeInterval? = nil,
        configRegistryIDs: [String]? = nil,
        configSigningKeys: [String]? = nil,
        freshnessSigningKeys: [String]? = nil,
        embeddedReferences: EmbeddedReferences? = nil,
        configAuthorizer: ConfigAuthorizer? = nil
    ) throws {
        let options = Options(
            pinnedRegisters: pinnedRegisters.map { .init(type: $0.type, registers: $0.registers) },
            freshnessMaxAgeNs: try freshnessMaxAge.map(Self.nanoseconds),
            configRegistryIDs: configRegistryIDs,
            configSigningKeysPEM: configSigningKeys,
            freshnessSigningKeysPEM: freshnessSigningKeys,
            embeddedConfig: embeddedReferences?.config.map(Options.EmbeddedConfig.init),
            embeddedRuntime: embeddedReferences?.runtime,
            embeddedPlatform: embeddedReferences?.platform
        )
        if let embeddedReferences, embeddedReferences.config == nil, embeddedReferences.runtime == nil,
           embeddedReferences.platform == nil {
            throw TinfoilError.configuration("embedded references must contain at least one component")
        }
        let optionsJSON = String(decoding: try JSONEncoder().encode(options), as: UTF8.self)
        backend = try GoAttestationVerifier(
            optionsJSON: optionsJSON,
            configAuthorizer: configAuthorizer.map(ConfigAuthorizerBridge.init)
        )
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

    /// The options JSON that the framework's verifier takes; nil members are
    /// left out, which keeps their defaults. Data encodes as standard base64.
    private struct Options: Encodable {
        struct Measurement: Encodable {
            let type: String
            let registers: [String]
        }

        struct RuntimeReference: Encodable {
            let repo: String
            let tag: String
            let digest: String
        }

        struct EmbeddedConfig: Encodable {
            let name: String?
            let bytes: Data?
            let digest: String?
            let runtime: RuntimeReference?

            init(_ config: Tinfoil.EmbeddedConfig) {
                switch config {
                case let .bytes(bytes, name):
                    self.name = name.isEmpty ? nil : name
                    self.bytes = bytes
                    self.digest = nil
                    self.runtime = nil
                case let .reference(digest, runtime, name):
                    self.name = name.isEmpty ? nil : name
                    self.bytes = nil
                    self.digest = digest
                    self.runtime = .init(repo: runtime.repo, tag: runtime.tag, digest: runtime.digest)
                }
            }
        }

        let pinnedRegisters: Measurement?
        let freshnessMaxAgeNs: Int64?
        let configRegistryIDs: [String]?
        let configSigningKeysPEM: [String]?
        let freshnessSigningKeysPEM: [String]?
        let embeddedConfig: EmbeddedConfig?
        let embeddedRuntime: Data?
        let embeddedPlatform: Data?

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

/// Caller-trusted components that replace their endorsements. Only the
/// components that are set are replaced; the hardware is always verified, and
/// so are the bindings between components and any pinned registers. Set at
/// least one.
public struct EmbeddedReferences: Sendable, Equatable {
    /// The deployment's config
    public var config: EmbeddedConfig?
    /// The runtime manifest that the config pins
    public var runtime: Data?
    /// A platform policy artifact (platform-endorsements/v2)
    public var platform: Data?

    public init(config: EmbeddedConfig? = nil, runtime: Data? = nil, platform: Data? = nil) {
        self.config = config
        self.runtime = runtime
        self.platform = platform
    }
}

/// A caller-trusted config: its exact bytes, or its digest and the runtime it
/// pins. `name` optionally gives either an `/org/project/revision` identity,
/// which a client's repo is then checked against.
public enum EmbeddedConfig: Sendable, Equatable {
    /// The config itself, and optionally its `/org/project/revision` name,
    /// which a client's repo is then checked against
    case bytes(Data, name: String = "")
    /// The config by its SHA-256 (lowercase hex) and the runtime release that
    /// it runs, and optionally its name
    case reference(digest: String, runtime: RuntimeReference, name: String = "")
}

/// A runtime release: its repository, tag and digest
public struct RuntimeReference: Sendable, Equatable {
    /// The `owner/name` repository the runtime is released from
    public let repo: String
    /// The release tag
    public let tag: String
    /// SHA-256 of the runtime artifact, lowercase hex
    public let digest: String

    public init(repo: String, tag: String, digest: String) {
        self.repo = repo
        self.tag = tag
        self.digest = digest
    }
}
