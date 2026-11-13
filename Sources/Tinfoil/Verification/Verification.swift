import Foundation

/// Called with the result of each verification a client makes: the router a
/// `RouterHTTPClient` picks, the verification each client makes before it
/// returns, and each later one, whether because the attestation expired, the
/// enclave rejected its key, or the caller asked. It only observes. A
/// cancelled run is not reported.
public typealias VerificationResultCallback = @Sendable (Result<Verification, TinfoilError>) -> Void

/// Called each time an enclave's evidence verifies, before the enclave is
/// used. Throw to reject it: discovery moves to the next router; otherwise
/// the run fails with `TinfoilError.attestationError` and the enclave's key is
/// never used. It runs synchronously, so keep it fast: requests waiting on a
/// refresh wait on it too.
public typealias VerificationCheck = @Sendable (Verification) throws -> Void

/// Identifies the software that performed verification
public struct SoftwareIdentity: Sendable, Equatable {
    /// The SDK's name, such as "tinfoil-swift"
    public let name: String
    /// The SDK's version, such as "0.9.0"
    public let version: String
}

/// How a verification was performed. The verifier fills it in from its own
/// state; none of it is attested by or checked against the document.
public struct VerificationMetadata: Sendable, Equatable {
    /// The SDK that performed the verification
    public let verifier: SoftwareIdentity
    /// When the document was appraised. It is not a freshness guarantee.
    public let verifiedAt: Date
}

/// Why a verification accepted a component's reference values. More sources
/// may be added, so match the ones you handle and tolerate any other.
public struct ReferenceSource: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    /// An endorsement in the document, verified against the trust policy
    public static let endorsement = ReferenceSource(rawValue: "endorsement")
    /// A value from the verifier's `EmbeddedReferences`
    public static let embedded = ReferenceSource(rawValue: "embedded")
    /// A config that the verifier's `ConfigAuthorizer` approved
    public static let policy = ReferenceSource(rawValue: "policy")

    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public var description: String { rawValue }
}

/// The config bound to the hardware. Only an endorsed config has a reference,
/// signing key hint, registry ID and times; the others are empty or nil.
public struct ConfigVerification: Sendable, Equatable {
    /// Why the config was accepted
    public let source: ReferenceSource
    /// The config's `/org/project/revision` identity, or empty
    public let name: String
    /// SHA-256 of the config, lowercase hex
    public let digest: String
    /// Identifies the endorsement: `sha256:` and the lowercase hex SHA-256 of
    /// its signed statement, as DSSE encodes it for signing
    public let reference: String
    /// Identifies the key that signed the approval: the standard base64
    /// SHA-256 of its DER `SubjectPublicKeyInfo`
    public let signingKeyHint: String
    /// When the config was approved, from the approval's authenticated
    /// RFC 3161 timestamp
    public let approvalTime: Date?
    /// The registry that approved the config, as its URI. For an approval
    /// signed with a certificate the certificate authenticates it;
    /// `Verifier.publicRegistryID` marks Tinfoil's public registry.
    public let registryID: String
    /// When a certificate-signed approval was signed, from its authenticated
    /// timestamp; nil for an approval signed with a pinned key
    public let signatureTime: Date?
}

/// A runtime or platform artifact that a config-based verification accepted.
/// An embedded artifact has no name, commit or approval time, and an embedded
/// platform has only a digest.
public struct ArtifactVerification: Sendable, Equatable {
    /// Why the artifact was accepted
    public let source: ReferenceSource
    /// The `owner/name` repository the artifact was released from
    public let repo: String
    /// The release tag, such as "v0.15.0"
    public let tag: String
    /// SHA-256 of the artifact, lowercase hex
    public let digest: String
    /// The artifact's name in its endorsement
    public let name: String
    /// The source commit the artifact was built from, lowercase hex
    public let commit: String
    /// When the artifact was approved, from its endorsement's authenticated
    /// timestamp
    public let approvalTime: Date?
}

/// What a verified attestation document proved about an enclave, and who
/// verified it. It holds no host: the document verifies the same whichever
/// host serves it, so the client's `enclave` records where it was fetched.
public struct Verification: Sendable, Equatable {
    /// A measurement: its predicate type and register values
    public struct Measurement: Sendable, Equatable, Decodable {
        public let type: String
        public let registers: [String]

        public init(type: String, registers: [String]) {
            self.type = type
            self.registers = registers
        }
    }

    /// A key the enclave endorses, bound into its hardware evidence
    public struct CryptoMaterial: Sendable, Equatable, Decodable {
        /// The item's name in the document, such as "tls" or "hpke"
        public let id: String
        /// A URI naming what the item is and how `data` encodes it, such as
        /// `https://tinfoil.sh/key/spki-fp-sha256/v1` for a TLS key
        /// fingerprint or `https://tinfoil.sh/key/x25519-hpke/v1` for an HPKE
        /// key; both are lowercase hex
        public let format: String
        /// The item, encoded as `format` says
        public let data: String
    }

    /// Repository the code provenance was authenticated against, without a tag
    /// or digest
    public let configRepo: String
    /// SHA-256 of the verified code release or runtime artifact, lowercase hex
    public let codeDigest: String
    /// The release tag of the verified code or runtime, or empty
    public let codeTag: String
    /// The registers the release fixes, in the enclave measurement's platform
    /// layout, with an empty register for one the release leaves open
    public let codeMeasurement: Measurement?
    /// The hardware quote's authenticated registers
    public let enclaveMeasurement: Measurement?
    /// The config bound to the hardware. Nil for an enclave verified against
    /// a code release, which has no config.
    public let config: ConfigVerification?
    /// The runtime that a config-based verification accepted
    public let runtime: ArtifactVerification?
    /// The platform endorsements that a config-based verification accepted
    public let platform: ArtifactVerification?
    /// SHA-256 of the enclave TLS certificate's public key, lowercase hex
    public let tlsPublicKeyFingerprint: String
    /// X25519 key that request bodies are encrypted to, lowercase hex. Empty
    /// for an enclave that endorses only a TLS key.
    public let hpkePublicKey: String
    /// Every endorsed key, including the two lifted out above
    public let cryptoMaterial: [CryptoMaterial]
    /// No new request may be authorized at or after this instant
    public let freshnessExpiresAt: Date
    /// How the verification was performed
    public let metadata: VerificationMetadata
}

extension Verification {
    /// The verifier payload schema this SDK decodes
    static let supportedSchemaVersion = 1

    /// Decodes the TinfoilGo verifier's JSON.
    init(payload: String) throws {
        let data = Data(payload.utf8)
        let decoder = JSONDecoder()
        // Read the version alone first, so a payload in another schema is
        // reported as such rather than as a missing field.
        let version: SchemaVersion
        do {
            version = try decoder.decode(SchemaVersion.self, from: data)
        } catch {
            throw TinfoilError.attestation("unreadable verification payload: \(error.localizedDescription)")
        }
        guard version.schemaVersion == Self.supportedSchemaVersion else {
            throw TinfoilError.attestation(
                "unsupported verification schema version \(version.schemaVersion); this SDK reads version \(Self.supportedSchemaVersion)"
            )
        }
        let decoded: Payload
        do {
            decoded = try decoder.decode(Payload.self, from: data)
        } catch {
            throw TinfoilError.attestation("unreadable verification payload: \(error.localizedDescription)")
        }

        self.init(
            configRepo: decoded.configRepo,
            codeDigest: decoded.codeDigest,
            codeTag: decoded.codeTag ?? "",
            codeMeasurement: decoded.codeMeasurement,
            enclaveMeasurement: decoded.enclaveMeasurement,
            config: try decoded.config.map { try $0.verification() },
            runtime: try decoded.runtime.map { try $0.verification() },
            platform: try decoded.platform.map { try $0.verification() },
            tlsPublicKeyFingerprint: decoded.tlsPublicKeyFP,
            hpkePublicKey: decoded.hpkePublicKey ?? "",
            cryptoMaterial: decoded.cryptoMaterial,
            freshnessExpiresAt: try Self.parseDate(decoded.freshnessExpiresAt, field: "freshness_expires_at"),
            metadata: VerificationMetadata(
                verifier: SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion),
                verifiedAt: try Self.parseDate(decoded.verifiedAt, field: "verified_at")
            )
        )
    }

    private struct SchemaVersion: Decodable {
        let schemaVersion: Int

        private enum CodingKeys: String, CodingKey {
            case schemaVersion = "schema_version"
        }
    }

    /// The payload as the TinfoilGo framework declares it, in its source's
    /// mobile/verification.go; a change there needs a matching change here.
    private struct Payload: Decodable {
        let configRepo: String
        let codeDigest: String
        let codeTag: String?
        let codeMeasurement: Measurement?
        let enclaveMeasurement: Measurement?
        let config: ConfigPayload?
        let runtime: ArtifactPayload?
        let platform: ArtifactPayload?
        let tlsPublicKeyFP: String
        let hpkePublicKey: String?
        let cryptoMaterial: [CryptoMaterial]
        let freshnessExpiresAt: String
        let verifiedAt: String

        private enum CodingKeys: String, CodingKey {
            case configRepo = "config_repo"
            case codeDigest = "code_digest"
            case codeTag = "code_tag"
            case codeMeasurement = "code_measurement"
            case enclaveMeasurement = "enclave_measurement"
            case config, runtime, platform
            case tlsPublicKeyFP = "tls_public_key_fp"
            case hpkePublicKey = "hpke_public_key"
            case cryptoMaterial = "crypto_material"
            case freshnessExpiresAt = "freshness_expires_at"
            case verifiedAt = "verified_at"
        }
    }

    private struct ConfigPayload: Decodable {
        let source: String
        let name: String?
        let digest: String
        let reference: String?
        let signingKeyHint: String?
        let approvalTime: String?
        let registryID: String?
        let signatureTime: String?

        private enum CodingKeys: String, CodingKey {
            case source, name, digest, reference
            case signingKeyHint = "signing_key_hint"
            case approvalTime = "approval_time"
            case registryID = "registry_id"
            case signatureTime = "signature_time"
        }

        func verification() throws -> ConfigVerification {
            ConfigVerification(
                source: ReferenceSource(rawValue: source),
                name: name ?? "",
                digest: digest,
                reference: reference ?? "",
                signingKeyHint: signingKeyHint ?? "",
                approvalTime: try approvalTime.map { try Verification.parseDate($0, field: "config.approval_time") },
                registryID: registryID ?? "",
                signatureTime: try signatureTime.map { try Verification.parseDate($0, field: "config.signature_time") }
            )
        }
    }

    private struct ArtifactPayload: Decodable {
        let source: String
        let repo: String?
        let tag: String?
        let digest: String
        let name: String?
        let commit: String?
        let approvalTime: String?

        private enum CodingKeys: String, CodingKey {
            case source, repo, tag, digest, name, commit
            case approvalTime = "approval_time"
        }

        func verification() throws -> ArtifactVerification {
            ArtifactVerification(
                source: ReferenceSource(rawValue: source),
                repo: repo ?? "",
                tag: tag ?? "",
                digest: digest,
                name: name ?? "",
                commit: commit ?? "",
                approvalTime: try approvalTime.map { try Verification.parseDate($0, field: "approval_time") }
            )
        }
    }

    /// The framework writes RFC 3339 and drops a zero fractional part, so
    /// both forms arrive. Each style is tried in turn because older Foundation
    /// releases parse only the form a style names.
    private static func parseDate(_ value: String, field: String) throws -> Date {
        let styles = [
            Date.ISO8601FormatStyle(includingFractionalSeconds: true),
            Date.ISO8601FormatStyle(),
        ]
        for style in styles {
            if let date = try? style.parse(value) {
                return date
            }
        }
        throw TinfoilError.attestation("verification payload has an invalid \(field): \(value)")
    }
}

extension TinfoilError {
    /// Classifies an error from the TinfoilGo verifier. It crosses the
    /// framework boundary as a message alone, led by its category's prefix,
    /// which is dropped here because the case carries the category. A
    /// verification error's message then names the layer that rejected the
    /// document, as in "quote: <detail>"; the layer is kept in the message and
    /// also lifted out. A message with neither prefix is treated as a rejected
    /// attestation.
    static func fromVerifier(
        _ error: Error,
        usagePrefix: String,
        verificationPrefix: String
    ) -> TinfoilError {
        let message = error.localizedDescription
        if message.hasPrefix(usagePrefix) {
            return .configuration(String(message.dropFirst(usagePrefix.count)))
        }
        if message.hasPrefix(verificationPrefix) {
            let rejection = String(message.dropFirst(verificationPrefix.count))
            return .attestation(rejection, layer: layer(leading: rejection))
        }
        return .attestation(message)
    }

    /// The layer a verification error's message leads with, as in
    /// "quote: <detail>". Layer names are single lowercase words, so a message
    /// whose text before ": " is anything else names no layer.
    private static func layer(leading message: String) -> VerificationLayer? {
        guard let separator = message.range(of: ": ") else {
            return nil
        }
        let name = message[..<separator.lowerBound]
        guard !name.isEmpty, name.allSatisfy({ $0.isASCII && $0.isLowercase }) else {
            return nil
        }
        return VerificationLayer(rawValue: String(name))
    }
}
