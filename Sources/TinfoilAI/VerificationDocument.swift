import Foundation

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