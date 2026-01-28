import Foundation

/// Callback type for verification events
/// - Parameter verificationDocument: The verification document from attestation
public typealias VerificationCallback = @Sendable (VerificationDocument?) -> Void

/// Represents the state of a verification step
public struct VerificationStepState: Codable {
    public enum Status: String, Codable {
        case pending
        case success
        case failed
    }

    public let status: Status
    public let error: String?

    public init(status: Status, error: String? = nil) {
        self.status = status
        self.error = error
    }

    public static func pending() -> VerificationStepState {
        return VerificationStepState(status: .pending)
    }

    public static func success() -> VerificationStepState {
        return VerificationStepState(status: .success)
    }

    public static func failed(_ error: String) -> VerificationStepState {
        return VerificationStepState(status: .failed, error: error)
    }
}

/// Represents an attestation measurement
public struct AttestationMeasurement: Codable {
    public let type: String
    public let registers: [String]

    public init(type: String, registers: [String]) {
        self.type = type
        self.registers = registers
    }
}

/// Represents an attestation response from the enclave
public struct AttestationResponse: Codable {
    public let measurement: AttestationMeasurement
    public let tlsPublicKeyFingerprint: String?
    public let hpkePublicKey: String?

    public init(
        measurement: AttestationMeasurement,
        tlsPublicKeyFingerprint: String? = nil,
        hpkePublicKey: String? = nil
    ) {
        self.measurement = measurement
        self.tlsPublicKeyFingerprint = tlsPublicKeyFingerprint
        self.hpkePublicKey = hpkePublicKey
    }
}

/// Hardware measurement for TDX platforms
public struct HardwareMeasurement: Codable {
    public let id: String
    public let mrtd: String
    public let rtmr0: String

    public init(id: String, mrtd: String, rtmr0: String) {
        self.id = id
        self.mrtd = mrtd
        self.rtmr0 = rtmr0
    }
}

/// Attestation document format and body
public struct AttestationDocument: Codable {
    public let format: String
    public let body: String

    public init(format: String, body: String) {
        self.format = format
        self.body = body
    }
}

/// Complete attestation bundle from single-request verification.
/// Contains all material needed for verification without additional network calls.
public struct AttestationBundle: Codable {
    /// Selected enclave domain hostname
    public let domain: String
    /// Enclave attestation report (from router's /.well-known/tinfoil-attestation)
    public let enclaveAttestationReport: AttestationDocument
    /// SHA256 digest of the release
    public let digest: String
    /// Sigstore bundle for code provenance verification (opaque JSON)
    public let sigstoreBundle: AnyCodable
    /// Base64-encoded VCEK certificate (DER format)
    public let vcek: String
    /// PEM-encoded enclave TLS certificate (contains HPKE key and attestation hash in SANs)
    public let enclaveCert: String

    public init(
        domain: String,
        enclaveAttestationReport: AttestationDocument,
        digest: String,
        sigstoreBundle: AnyCodable,
        vcek: String,
        enclaveCert: String
    ) {
        self.domain = domain
        self.enclaveAttestationReport = enclaveAttestationReport
        self.digest = digest
        self.sigstoreBundle = sigstoreBundle
        self.vcek = vcek
        self.enclaveCert = enclaveCert
    }
}

/// Type-erased Codable wrapper for arbitrary JSON values
public struct AnyCodable: Codable {
    public let value: Any

    public init(_ value: Any) {
        self.value = value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if container.decodeNil() {
            self.value = NSNull()
        } else if let bool = try? container.decode(Bool.self) {
            self.value = bool
        } else if let int = try? container.decode(Int.self) {
            self.value = int
        } else if let double = try? container.decode(Double.self) {
            self.value = double
        } else if let string = try? container.decode(String.self) {
            self.value = string
        } else if let array = try? container.decode([AnyCodable].self) {
            self.value = array.map { $0.value }
        } else if let dictionary = try? container.decode([String: AnyCodable].self) {
            self.value = dictionary.mapValues { $0.value }
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unable to decode value")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        switch value {
        case is NSNull:
            try container.encodeNil()
        case let bool as Bool:
            try container.encode(bool)
        case let int as Int:
            try container.encode(int)
        case let double as Double:
            try container.encode(double)
        case let string as String:
            try container.encode(string)
        case let array as [Any]:
            try container.encode(array.map { AnyCodable($0) })
        case let dictionary as [String: Any]:
            try container.encode(dictionary.mapValues { AnyCodable($0) })
        default:
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: encoder.codingPath, debugDescription: "Unable to encode value"))
        }
    }
}

/// Complete verification document containing all verification details
public struct VerificationDocument: Codable {
    public let configRepo: String
    public let enclaveHost: String
    public let releaseDigest: String
    public let codeMeasurement: AttestationMeasurement
    public let enclaveMeasurement: AttestationResponse
    public let tlsPublicKey: String
    public let hpkePublicKey: String
    public let hardwareMeasurement: HardwareMeasurement?
    public let codeFingerprint: String
    public let enclaveFingerprint: String
    public let selectedRouterEndpoint: String
    public let securityVerified: Bool

    /// Detailed step-by-step verification status
    public struct Steps: Codable {
        public let fetchDigest: VerificationStepState
        public let verifyCode: VerificationStepState
        public let verifyEnclave: VerificationStepState
        public let compareMeasurements: VerificationStepState
        public let createTransport: VerificationStepState?
        public let verifyHPKEKey: VerificationStepState?
        public let otherError: VerificationStepState?

        public init(
            fetchDigest: VerificationStepState = .pending(),
            verifyCode: VerificationStepState = .pending(),
            verifyEnclave: VerificationStepState = .pending(),
            compareMeasurements: VerificationStepState = .pending(),
            createTransport: VerificationStepState? = nil,
            verifyHPKEKey: VerificationStepState? = nil,
            otherError: VerificationStepState? = nil
        ) {
            self.fetchDigest = fetchDigest
            self.verifyCode = verifyCode
            self.verifyEnclave = verifyEnclave
            self.compareMeasurements = compareMeasurements
            self.createTransport = createTransport
            self.verifyHPKEKey = verifyHPKEKey
            self.otherError = otherError
        }
    }

    public let steps: Steps

    public init(
        configRepo: String,
        enclaveHost: String,
        releaseDigest: String,
        codeMeasurement: AttestationMeasurement,
        enclaveMeasurement: AttestationResponse,
        tlsPublicKey: String,
        hpkePublicKey: String,
        hardwareMeasurement: HardwareMeasurement?,
        codeFingerprint: String,
        enclaveFingerprint: String,
        selectedRouterEndpoint: String,
        securityVerified: Bool,
        steps: Steps
    ) {
        self.configRepo = configRepo
        self.enclaveHost = enclaveHost
        self.releaseDigest = releaseDigest
        self.codeMeasurement = codeMeasurement
        self.enclaveMeasurement = enclaveMeasurement
        self.tlsPublicKey = tlsPublicKey
        self.hpkePublicKey = hpkePublicKey
        self.hardwareMeasurement = hardwareMeasurement
        self.codeFingerprint = codeFingerprint
        self.enclaveFingerprint = enclaveFingerprint
        self.selectedRouterEndpoint = selectedRouterEndpoint
        self.securityVerified = securityVerified
        self.steps = steps
    }
}

/// Extension to provide easy access to verification results
public extension VerificationDocument {
    /// Check if all verification steps succeeded
    var allStepsSucceeded: Bool {
        return steps.fetchDigest.status == .success &&
               steps.verifyCode.status == .success &&
               steps.verifyEnclave.status == .success &&
               steps.compareMeasurements.status == .success
    }

    /// Get a human-readable summary of the verification
    var summary: String {
        if securityVerified && allStepsSucceeded {
            return "Verification successful: Code and runtime measurements match"
        } else if let error = getFirstError() {
            return "Verification failed: \(error)"
        } else {
            return "Verification incomplete"
        }
    }

    /// Get the first error encountered during verification
    func getFirstError() -> String? {
        if let error = steps.fetchDigest.error { return error }
        if let error = steps.verifyCode.error { return error }
        if let error = steps.verifyEnclave.error { return error }
        if let error = steps.compareMeasurements.error { return error }
        if let error = steps.createTransport?.error { return error }
        if let error = steps.verifyHPKEKey?.error { return error }
        if let error = steps.otherError?.error { return error }
        return nil
    }
}