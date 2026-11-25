import Foundation

/// Called once for every attempt that a client makes to verify an enclave,
/// after the attempt's outcome is decided: the first verification, each
/// retry, each router that discovery tries, and every later verification,
/// whether because the attestation expired, the enclave rejected its key, or
/// the caller asked. It receives the host of the enclave that the attempt
/// verified and the outcome that `lastVerification` returns for it. It only
/// observes; reject an enclave with `VerificationCheck`.
///
/// The client calls it outside its actors, so that the callback can call the
/// client, but requests that wait for the verification wait for it too, so
/// keep it fast. An attempt that the client's close ended is not reported.
public typealias VerificationCallback = @Sendable (_ host: String, _ result: Result<VerificationReport, TinfoilError>) -> Void

/// Called each time an enclave's evidence verifies, with the verified facts,
/// before the enclave is used. Throw to reject it: discovery moves to the
/// next router; otherwise the attempt fails with
/// `TinfoilError.attestationError` and the enclave's key is never used. It
/// runs synchronously, so keep it fast: requests that wait on a refresh wait
/// on it too.
public typealias VerificationCheck = @Sendable (VerifiedFacts) throws -> Void

/// Identifies the software that performed verification
public struct SoftwareIdentity: Sendable, Equatable, Encodable {
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
/// may be added, so match the ones that you handle and tolerate any other.
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
    /// `Trust.publicRegistryID` marks Tinfoil's public registry.
    public let registryID: String
    /// When a certificate-signed approval was signed, from its authenticated
    /// timestamp; nil for an approval signed with a pinned key
    public let signatureTime: Date?
}

/// A code release, or a runtime or platform artifact that a config-based
/// verification accepted. An embedded artifact has no name, commit or
/// approval time, and an embedded platform has only a digest.
public struct ArtifactVerification: Sendable, Equatable {
    /// Why the artifact was accepted
    public let source: ReferenceSource
    /// The `owner/name` repository that the artifact was released from
    public let repo: String
    /// The release tag, such as "v0.15.0"
    public let tag: String
    /// SHA-256 of the artifact, lowercase hex
    public let digest: String
    /// The artifact's name in its endorsement
    public let name: String
    /// The source commit that the artifact was built from, lowercase hex
    public let commit: String
    /// When the artifact was approved, from its endorsement's authenticated
    /// timestamp
    public let approvalTime: Date?
}

/// What a successful verification proved about an enclave: the result that
/// a `VerificationReport` carries once every step passed. It holds no host:
/// the document verifies the same whichever host serves it, so the client
/// records where it was fetched. The verifier's metadata is on the report.
///
/// Verified facts are the only source of channel keys: a client binds TLS or
/// EHBP only to the keys here, never to anything in `PartialFacts`, and never
/// to a key that was read from the facts' JSON form. Only verification creates
/// them: they are `Encodable` but not `Decodable`.
public struct VerifiedFacts: Sendable, Equatable {
    /// A measurement: its predicate type and register values, in the
    /// platform's order, with an empty register for one that is
    /// unconstrained. The JSON form names the registers instead: SEV-SNP
    /// (`https://tinfoil.sh/predicate/sev-snp-guest/v2`) as
    /// `{"platform": "sev-snp", "launch"}`, and TDX
    /// (`https://tinfoil.sh/predicate/tdx-guest/v2`) as
    /// `{"platform": "tdx", "mrtd", "rtmr0", ..., "rtmr3"}`, without an
    /// empty register.
    public struct Measurement: Sendable, Equatable {
        public let type: String
        public let registers: [String]

        public init(type: String, registers: [String]) {
            self.type = type
            self.registers = registers
        }
    }

    /// A key that the enclave endorses, bound into its hardware evidence
    public struct CryptoMaterial: Sendable, Equatable, Encodable {
        /// The item's name in the document, such as "tls" or "hpke"
        public let id: String
        /// A URI naming what the item is and how `data` encodes it, such as
        /// `https://tinfoil.sh/key/spki-fp-sha256/v1` for a TLS key
        /// fingerprint or `https://tinfoil.sh/key/x25519-hpke/v1` for an HPKE
        /// key; both are lowercase hex
        public let format: String
        /// The item, encoded as `format` says
        public let data: String

        /// The format of the TLS key's fingerprint, which the item with id
        /// "tls" has
        static let tlsFormat = "https://tinfoil.sh/key/spki-fp-sha256/v1"
        /// The format of the HPKE key, which the item with id "hpke" has
        static let hpkeFormat = "https://tinfoil.sh/key/x25519-hpke/v1"
    }

    /// Repository that the code provenance was authenticated against, without
    /// a tag or digest
    public let configRepo: String
    /// SHA-256 of the verified code release or runtime artifact, lowercase hex
    public let codeDigest: String
    /// The release tag of the verified code or runtime, or empty
    public let codeTag: String
    /// The registers that the release fixes, in the enclave measurement's
    /// platform layout, with an empty register for one that the release
    /// leaves open
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
    /// SHA-256 of the enclave TLS certificate's public key, lowercase hex:
    /// the `cryptoMaterial` item with id "tls" in the
    /// `https://tinfoil.sh/key/spki-fp-sha256/v1` format, or empty if the
    /// document endorses none. The JSON form has it only in `crypto_material`.
    public let tlsPublicKeyFingerprint: String
    /// X25519 key that request bodies are encrypted to, lowercase hex: the
    /// `cryptoMaterial` item with id "hpke" in the
    /// `https://tinfoil.sh/key/x25519-hpke/v1` format. Empty for an enclave
    /// that endorses only a TLS key. The JSON form has it only in
    /// `crypto_material`.
    public let hpkePublicKey: String
    /// Every endorsed key, including the two that are lifted out above, in
    /// the document's order
    public let cryptoMaterial: [CryptoMaterial]
    /// No new request may be authorized at or after this instant
    public let freshnessExpiresAt: Date
}
