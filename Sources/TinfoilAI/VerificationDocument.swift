import Foundation

/// Callback type for verification events
/// - Parameter verificationDocument: The verification document from attestation
public typealias VerificationCallback = @Sendable (VerificationDocument?) -> Void

/// Represents the state of a verification step
public struct VerificationStepState: Codable {
    public enum Status: String, Codable, Hashable {
        case pending
        case success
        case failed
        case skipped
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

    public static func skipped() -> VerificationStepState {
        return VerificationStepState(status: .skipped)
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

    private enum CodingKeys: String, CodingKey {
        case id = "ID"
        case mrtd = "MRTD"
        case rtmr0 = "RTMR0"
    }

    private enum LegacyCodingKeys: String, CodingKey {
        case id
        case mrtd
        case rtmr0
    }

    public init(from decoder: Decoder) throws {
        let canonical = try decoder.container(keyedBy: CodingKeys.self)
        if canonical.contains(.id) {
            id = try canonical.decode(String.self, forKey: .id)
            mrtd = try canonical.decode(String.self, forKey: .mrtd)
            rtmr0 = try canonical.decode(String.self, forKey: .rtmr0)
        } else {
            let legacy = try decoder.container(keyedBy: LegacyCodingKeys.self)
            id = try legacy.decode(String.self, forKey: .id)
            mrtd = try legacy.decode(String.self, forKey: .mrtd)
            rtmr0 = try legacy.decode(String.self, forKey: .rtmr0)
        }
    }
}

/// Identifies the software that performed verification
public struct SoftwareIdentity: Codable {
    public let name: String
    public let version: String

    public init(name: String, version: String) {
        self.name = name
        self.version = version
    }
}

/// Complete verification document containing all verification details
public struct VerificationDocument: Codable {
    public let schemaVersion: Int
    public let configRepo: String
    public let enclaveHost: String
    public let releaseTag: String?
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
    public let verifier: SoftwareIdentity
    public let verifiedAt: String?

    /// Detailed step-by-step verification status
    public struct Steps: Codable {
        public let fetchDigest: VerificationStepState
        public let verifyCode: VerificationStepState
        public let verifyEnclave: VerificationStepState
        public let compareMeasurements: VerificationStepState
        public let verifyCertificate: VerificationStepState
        internal let includesVerifyCertificate: Bool
        public let createTransport: VerificationStepState?
        public let verifyHPKEKey: VerificationStepState?
        public let otherError: VerificationStepState?

        public init(
            fetchDigest: VerificationStepState = .pending(),
            verifyCode: VerificationStepState = .pending(),
            verifyEnclave: VerificationStepState = .pending(),
            compareMeasurements: VerificationStepState = .pending(),
            verifyCertificate: VerificationStepState = .pending(),
            createTransport: VerificationStepState? = nil,
            verifyHPKEKey: VerificationStepState? = nil,
            otherError: VerificationStepState? = nil
        ) {
            self.fetchDigest = fetchDigest
            self.verifyCode = verifyCode
            self.verifyEnclave = verifyEnclave
            self.compareMeasurements = compareMeasurements
            self.verifyCertificate = verifyCertificate
            self.includesVerifyCertificate = true
            self.createTransport = createTransport
            self.verifyHPKEKey = verifyHPKEKey
            self.otherError = otherError
        }

        fileprivate enum CodingKeys: String, CodingKey {
            case fetchDigest
            case verifyCode
            case verifyEnclave
            case compareMeasurements
            case verifyCertificate
            case createTransport
            case verifyHPKEKey
            case otherError
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            fetchDigest = try container.decode(VerificationStepState.self, forKey: .fetchDigest)
            verifyCode = try container.decode(VerificationStepState.self, forKey: .verifyCode)
            verifyEnclave = try container.decode(VerificationStepState.self, forKey: .verifyEnclave)
            compareMeasurements = try container.decode(VerificationStepState.self, forKey: .compareMeasurements)
            verifyCertificate = try container.decodeIfPresent(VerificationStepState.self, forKey: .verifyCertificate) ?? .pending()
            includesVerifyCertificate = container.contains(.verifyCertificate)
            createTransport = try container.decodeIfPresent(VerificationStepState.self, forKey: .createTransport)
            verifyHPKEKey = try container.decodeIfPresent(VerificationStepState.self, forKey: .verifyHPKEKey)
            otherError = try container.decodeIfPresent(VerificationStepState.self, forKey: .otherError)
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
        steps: Steps,
        schemaVersion: Int = 1,
        releaseTag: String? = nil,
        verifier: SoftwareIdentity = SoftwareIdentity(
            name: TinfoilConstants.verifierName,
            version: TinfoilConstants.verifierVersion
        ),
        verifiedAt: String? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.configRepo = configRepo
        self.enclaveHost = enclaveHost
        self.releaseTag = releaseTag
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
        self.verifier = verifier
        self.verifiedAt = verifiedAt
        self.steps = steps
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case configRepo
        case enclaveHost
        case releaseTag
        case releaseDigest
        case codeMeasurement
        case enclaveMeasurement
        case tlsPublicKey
        case hpkePublicKey
        case hardwareMeasurement
        case codeFingerprint
        case enclaveFingerprint
        case selectedRouterEndpoint
        case securityVerified
        case verifier
        case verifiedAt
        case steps
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 0
        configRepo = try container.decode(String.self, forKey: .configRepo)
        enclaveHost = try container.decode(String.self, forKey: .enclaveHost)
        releaseTag = try container.decodeIfPresent(String.self, forKey: .releaseTag)
        releaseDigest = try container.decode(String.self, forKey: .releaseDigest)
        codeMeasurement = try container.decode(AttestationMeasurement.self, forKey: .codeMeasurement)
        enclaveMeasurement = try container.decode(AttestationResponse.self, forKey: .enclaveMeasurement)
        tlsPublicKey = try container.decode(String.self, forKey: .tlsPublicKey)
        hpkePublicKey = try container.decode(String.self, forKey: .hpkePublicKey)
        hardwareMeasurement = try container.decodeIfPresent(HardwareMeasurement.self, forKey: .hardwareMeasurement)
        codeFingerprint = try container.decode(String.self, forKey: .codeFingerprint)
        enclaveFingerprint = try container.decode(String.self, forKey: .enclaveFingerprint)
        selectedRouterEndpoint = try container.decode(String.self, forKey: .selectedRouterEndpoint)
        securityVerified = try container.decode(Bool.self, forKey: .securityVerified)
        if schemaVersion == 0 {
            verifier = try container.decodeIfPresent(SoftwareIdentity.self, forKey: .verifier)
                ?? SoftwareIdentity(name: "unknown", version: "unknown")
        } else {
            verifier = try container.decode(SoftwareIdentity.self, forKey: .verifier)
        }
        verifiedAt = try container.decodeIfPresent(String.self, forKey: .verifiedAt)
        steps = try container.decode(Steps.self, forKey: .steps)
        if schemaVersion == 1 && !steps.includesVerifyCertificate {
            throw DecodingError.keyNotFound(
                Steps.CodingKeys.verifyCertificate,
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "schemaVersion 1 requires verifyCertificate"
                )
            )
        }
    }
}

/// Extension to provide easy access to verification results
public extension VerificationDocument {
    /// Check if all verification steps succeeded
    var allStepsSucceeded: Bool {
        let completed: Set<VerificationStepState.Status> = [.success, .skipped]
        return completed.contains(steps.fetchDigest.status) &&
               completed.contains(steps.verifyCode.status) &&
               completed.contains(steps.verifyEnclave.status) &&
               completed.contains(steps.compareMeasurements.status) &&
               completed.contains(steps.verifyCertificate.status)
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
        if let error = steps.verifyCertificate.error { return error }
        if let error = steps.createTransport?.error { return error }
        if let error = steps.verifyHPKEKey?.error { return error }
        if let error = steps.otherError?.error { return error }
        return nil
    }
}

internal extension VerificationDocument {
    func replacingVerifier(_ verifier: SoftwareIdentity) -> VerificationDocument {
        VerificationDocument(
            configRepo: configRepo,
            enclaveHost: enclaveHost,
            releaseDigest: releaseDigest,
            codeMeasurement: codeMeasurement,
            enclaveMeasurement: enclaveMeasurement,
            tlsPublicKey: tlsPublicKey,
            hpkePublicKey: hpkePublicKey,
            hardwareMeasurement: hardwareMeasurement,
            codeFingerprint: codeFingerprint,
            enclaveFingerprint: enclaveFingerprint,
            selectedRouterEndpoint: selectedRouterEndpoint,
            securityVerified: securityVerified,
            steps: steps,
            schemaVersion: schemaVersion,
            releaseTag: releaseTag,
            verifier: verifier,
            verifiedAt: verifiedAt
        )
    }
}
