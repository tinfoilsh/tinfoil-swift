import Foundation

/// Called with the result of each `EnclaveHandle.verify()` run: for a
/// `TinfoilAI` client, once when it is created and again whenever it
/// re-verifies because the attestation expired or the enclave rejected its
/// key. It only observes. A cancelled run is not reported.
public typealias VerificationResultCallback = @Sendable (Result<Verification, TinfoilError>) -> Void

/// Called each time an enclave's evidence verifies, before the enclave is
/// used. Throw to reject it: discovery moves to the next router; otherwise
/// the run fails with `TinfoilError.enclaveRejected` and the enclave's key is
/// never used. It runs synchronously, so keep it fast: requests waiting on a
/// refresh wait on it too.
public typealias EnclaveVerifiedCallback = @Sendable (Verification) throws -> Void

/// Identifies the software that performed verification
public struct SoftwareIdentity: Codable, Sendable, Equatable {
    public let name: String
    public let version: String

    public init(name: String, version: String) {
        self.name = name
        self.version = version
    }
}

/// Checks a verification makes beyond the defaults
public struct VerificationPolicy: Equatable, Sendable {
    /// Register values the enclave measurement must also match. An empty
    /// register keeps its default check.
    public var pinnedRegisters: Verification.Measurement?
    /// Oldest freshness witness accepted. Nil keeps the seven-day default.
    public var freshnessMaxAge: TimeInterval?

    public init(pinnedRegisters: Verification.Measurement? = nil, freshnessMaxAge: TimeInterval? = nil) {
        self.pinnedRegisters = pinnedRegisters
        self.freshnessMaxAge = freshnessMaxAge
    }
}

/// What a verified attestation document proved about an enclave, together with
/// the SDK's own record of where it asked and who verified.
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
        public let id: String
        public let format: String
        public let data: String
    }

    /// Host the document was fetched for. Nothing attests it; it records where
    /// the SDK asked.
    public let enclaveHost: String
    /// Repository the code provenance was authenticated against, without a tag
    /// or digest
    public let configRepo: String
    public let codeDigest: String
    public let codeTag: String?
    public let codeMeasurement: Measurement?
    /// The hardware quote's authenticated registers
    public let enclaveMeasurement: Measurement?
    /// SHA-256 of the enclave TLS certificate's public key, lowercase hex
    public let tlsPublicKeyFingerprint: String
    /// X25519 key that request bodies are encrypted to, lowercase hex. Absent
    /// for an enclave that endorses only a TLS key.
    public let hpkePublicKey: String?
    /// Every endorsed key, including the two lifted out above
    public let cryptoMaterial: [CryptoMaterial]
    /// No new request may be authorized at or after this instant
    public let freshnessExpiresAt: Date
    /// When the document was appraised
    public let verifiedAt: Date
    /// The SDK that performed the verification
    public let verifier: SoftwareIdentity
}

extension Verification {
    /// The verifier payload schema this SDK decodes
    static let supportedSchemaVersion = 1

    /// Decodes the Go verifier's JSON for a document fetched from enclaveHost.
    init(payload: String, enclaveHost: String) throws {
        let data = Data(payload.utf8)
        let decoder = JSONDecoder()
        // Read the version alone first, so a payload in another schema is
        // reported as such rather than as a missing field.
        let version: SchemaVersion
        do {
            version = try decoder.decode(SchemaVersion.self, from: data)
        } catch {
            throw TinfoilError.attestationError("unreadable verification payload: \(error.localizedDescription)")
        }
        guard version.schemaVersion == Self.supportedSchemaVersion else {
            throw TinfoilError.attestationError(
                "unsupported verification schema version \(version.schemaVersion); this SDK reads version \(Self.supportedSchemaVersion)"
            )
        }
        let decoded: Payload
        do {
            decoded = try decoder.decode(Payload.self, from: data)
        } catch {
            throw TinfoilError.attestationError("unreadable verification payload: \(error.localizedDescription)")
        }

        self.init(
            enclaveHost: enclaveHost,
            configRepo: decoded.configRepo,
            codeDigest: decoded.codeDigest,
            codeTag: decoded.codeTag,
            codeMeasurement: decoded.codeMeasurement,
            enclaveMeasurement: decoded.enclaveMeasurement,
            tlsPublicKeyFingerprint: decoded.tlsPublicKeyFP,
            hpkePublicKey: decoded.hpkePublicKey,
            cryptoMaterial: decoded.cryptoMaterial,
            freshnessExpiresAt: try Self.parseDate(decoded.freshnessExpiresAt, field: "freshness_expires_at"),
            verifiedAt: try Self.parseDate(decoded.verifiedAt, field: "verified_at"),
            verifier: SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion)
        )
    }

    private struct SchemaVersion: Decodable {
        let schemaVersion: Int

        private enum CodingKeys: String, CodingKey {
            case schemaVersion = "schema_version"
        }
    }

    /// The payload as mobile/verification.go in tinfoil-go declares it
    private struct Payload: Decodable {
        let configRepo: String
        let codeDigest: String
        let codeTag: String?
        let codeMeasurement: Measurement?
        let enclaveMeasurement: Measurement?
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
            case tlsPublicKeyFP = "tls_public_key_fp"
            case hpkePublicKey = "hpke_public_key"
            case cryptoMaterial = "crypto_material"
            case freshnessExpiresAt = "freshness_expires_at"
            case verifiedAt = "verified_at"
        }
    }

    /// Go writes RFC 3339 and drops a zero fractional part, so both forms
    /// arrive. Each style is tried in turn because older Foundation releases
    /// parse only the form a style names.
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
        throw TinfoilError.attestationError("verification payload has an invalid \(field): \(value)")
    }
}

extension TinfoilError {
    /// Classifies an error from the Go verifier. It crosses the FFI as a
    /// message alone, led by its category's prefix, which is dropped here
    /// because the case carries the category. A message with neither prefix
    /// is treated as a rejected attestation.
    static func fromVerifier(
        _ error: Error,
        configurationPrefix: String,
        attestationPrefix: String
    ) -> TinfoilError {
        let message = error.localizedDescription
        if message.hasPrefix(configurationPrefix) {
            return .invalidConfiguration(String(message.dropFirst(configurationPrefix.count)))
        }
        if message.hasPrefix(attestationPrefix) {
            return .attestationError(String(message.dropFirst(attestationPrefix.count)))
        }
        return .attestationError(message)
    }
}
