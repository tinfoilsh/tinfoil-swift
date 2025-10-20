import Foundation
import TinfoilVerifier

/// Represents the status of a verification step
public enum VerificationStatus {
    case pending
    case inProgress
    case success
    case failure(Error)
}

/// Errors that can occur during verification
public enum VerificationError: Error {
    case verificationFailed(String)
    case jsonDecodingFailed(String)
    case unknown(Error)
}

/// Contains verification result information for a step
public struct StepResult {
    public let status: VerificationStatus
    public let digest: String?
    
    public static func pending() -> StepResult {
        return StepResult(status: .pending, digest: nil)
    }
    
    public static func inProgress() -> StepResult {
        return StepResult(status: .inProgress, digest: nil)
    }
    
    public static func success(digest: String) -> StepResult {
        return StepResult(status: .success, digest: digest)
    }
    
    public static func failure(_ error: Error) -> StepResult {
        return StepResult(status: .failure(error), digest: nil)
    }
}

/// Progress callbacks for verification steps
public struct VerificationCallbacks {
    public let onVerificationStart: () -> Void
    public let onVerificationComplete: (Result<GroundTruth, Error>) -> Void
    
    public init(
        onVerificationStart: @escaping () -> Void = { },
        onVerificationComplete: @escaping (Result<GroundTruth, Error>) -> Void = { _ in }
    ) {
        self.onVerificationStart = onVerificationStart
        self.onVerificationComplete = onVerificationComplete
    }
}

/// Measurement structure matching Go's attestation.Measurement
public struct Measurement: Codable {
    public let type: String
    public let registers: [String]
    
    private enum CodingKeys: String, CodingKey {
        case type
        case registers
    }
}

/// Ground truth structure matching Go's client.GroundTruth
public struct GroundTruth: Codable {
    public let tlsPublicKey: String
    public let hpkePublicKey: String?
    public let digest: String
    public let codeMeasurement: Measurement?
    public let enclaveMeasurement: Measurement?
    public let hardwarePlatform: String?
    
    private enum CodingKeys: String, CodingKey {
        case tlsPublicKey = "tls_public_key"
        case hpkePublicKey = "hpke_public_key"
        case digest
        case codeMeasurement = "code_measurement"
        case enclaveMeasurement = "enclave_measurement"
        case hardwarePlatform = "hardware_platform"
    }
}

/// A client for securely verifying code integrity through remote attestation
public class SecureClient {
    private let githubRepo: String
    private let enclaveURL: String
    private let callbacks: VerificationCallbacks
    private var groundTruth: GroundTruth?
    private var lastVerificationDocument: VerificationDocument?
    
    /// Initialize a secure client with required configuration
    /// - Parameters:
    ///   - githubRepo: GitHub repository in the format "org/repo"
    ///   - enclaveURL: URL for the enclave attestation endpoint
    ///   - callbacks: Optional callbacks for verification progress
    public init(
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        enclaveURL: String,
        callbacks: VerificationCallbacks = VerificationCallbacks()
    ) {
        self.githubRepo = githubRepo
        self.enclaveURL = enclaveURL
        self.callbacks = callbacks
    }
    
    /// Returns the last verified ground truth
    public func getGroundTruth() -> GroundTruth? {
        return groundTruth
    }

    /// Returns the full verification document from the last verification attempt
    public func getVerificationDocument() -> VerificationDocument? {
        return lastVerificationDocument
    }
    
    /// Verifies the committed code and runtime binaries using remote attestation
    /// - Returns: The ground truth containing all verification results
    public func verify() async throws -> GroundTruth {
        callbacks.onVerificationStart()

        // Initialize verification steps
        var steps = VerificationDocument.Steps()

        // Parse the enclave URL to extract the host
        let urlComponents: (url: URL, host: String, scheme: String, port: Int?)
        do {
            urlComponents = try URLHelpers.parseURL(enclaveURL)
        } catch {
            let verificationError = VerificationError.verificationFailed("Invalid enclave URL: \(error.localizedDescription)")
            buildFailureDocument(error: verificationError, steps: steps)
            callbacks.onVerificationComplete(.failure(verificationError))
            throw verificationError
        }

        // Create a new TinfoilVerifier secure client
        guard let client = TinfoilVerifier.ClientNewSecureClient(urlComponents.host, githubRepo) else {
            let error = VerificationError.verificationFailed("Failed to create secure client")
            buildFailureDocument(error: error, steps: steps)
            callbacks.onVerificationComplete(.failure(error))
            throw error
        }

        // Run verification - this performs all steps internally
        steps = VerificationDocument.Steps(
            fetchDigest: .pending(),
            verifyCode: .pending(),
            verifyEnclave: .pending(),
            compareMeasurements: .pending()
        )

        do {
            _ = try client.verify()
        } catch {
            // The verification failed - mark appropriate steps as failed
            let verificationError = VerificationError.verificationFailed("Verification failed: \(error.localizedDescription)")

            // Determine which step failed based on the error message
            if error.localizedDescription.contains("measurement mismatch") {
                steps = VerificationDocument.Steps(
                    fetchDigest: .success(),
                    verifyCode: .success(),
                    verifyEnclave: .success(),
                    compareMeasurements: .failed(error.localizedDescription)
                )
            } else {
                // Generic failure - we don't know exactly which step failed
                steps = VerificationDocument.Steps(
                    fetchDigest: .failed(error.localizedDescription),
                    verifyCode: .failed(error.localizedDescription),
                    verifyEnclave: .failed(error.localizedDescription),
                    compareMeasurements: .failed(error.localizedDescription)
                )
            }

            buildFailureDocument(error: verificationError, steps: steps)
            callbacks.onVerificationComplete(.failure(verificationError))
            throw verificationError
        }

        // Get the ground truth as JSON string from the client
        var jsonError: NSError?
        let jsonString = client.groundTruthJSON(&jsonError)

        if let error = jsonError {
            let verificationError = VerificationError.jsonDecodingFailed(error.localizedDescription)
            steps = VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .success(),
                verifyEnclave: .success(),
                compareMeasurements: .success(),
                otherError: .failed("Failed to retrieve verification result: \(error.localizedDescription)")
            )
            buildFailureDocument(error: verificationError, steps: steps)
            callbacks.onVerificationComplete(.failure(verificationError))
            throw verificationError
        }

        guard let jsonData = jsonString.data(using: String.Encoding.utf8) else {
            let verificationError = VerificationError.jsonDecodingFailed("Failed to convert JSON string to data")
            steps = VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .success(),
                verifyEnclave: .success(),
                compareMeasurements: .success(),
                otherError: .failed("Failed to process verification result")
            )
            buildFailureDocument(error: verificationError, steps: steps)
            callbacks.onVerificationComplete(.failure(verificationError))
            throw verificationError
        }

        // Decode the ground truth JSON
        let decoder = JSONDecoder()
        do {
            let groundTruth = try decoder.decode(GroundTruth.self, from: jsonData)
            self.groundTruth = groundTruth

            // Build successful verification document
            steps = VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .success(),
                verifyEnclave: .success(),
                compareMeasurements: .success()
            )

            // Create attestation structures from ground truth
            let codeMeasurement = AttestationMeasurement(
                type: groundTruth.codeMeasurement?.type ?? "",
                registers: groundTruth.codeMeasurement?.registers ?? []
            )

            let enclaveMeasurement = AttestationResponse(
                measurement: AttestationMeasurement(
                    type: groundTruth.enclaveMeasurement?.type ?? "",
                    registers: groundTruth.enclaveMeasurement?.registers ?? []
                ),
                tlsPublicKeyFingerprint: groundTruth.tlsPublicKey.isEmpty ? nil : groundTruth.tlsPublicKey,
                hpkePublicKey: groundTruth.hpkePublicKey
            )

            lastVerificationDocument = VerificationDocument(
                configRepo: githubRepo,
                enclaveHost: urlComponents.host,
                releaseDigest: groundTruth.digest,
                codeMeasurement: codeMeasurement,
                enclaveMeasurement: enclaveMeasurement,
                securityVerified: true,
                steps: steps
            )

            callbacks.onVerificationComplete(.success(groundTruth))
            return groundTruth
        } catch {
            let decodingError = VerificationError.jsonDecodingFailed(error.localizedDescription)
            steps = VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .success(),
                verifyEnclave: .success(),
                compareMeasurements: .success(),
                otherError: .failed("Failed to decode verification result: \(error.localizedDescription)")
            )
            buildFailureDocument(error: decodingError, steps: steps)
            callbacks.onVerificationComplete(.failure(decodingError))
            throw decodingError
        }
    }

    /// Helper method to build a failure verification document
    private func buildFailureDocument(error: Error, steps: VerificationDocument.Steps) {
        // Parse the enclave URL if possible
        let host = (try? URLHelpers.parseURL(enclaveURL))?.host ?? enclaveURL

        lastVerificationDocument = VerificationDocument(
            configRepo: githubRepo,
            enclaveHost: host,
            releaseDigest: "",
            codeMeasurement: AttestationMeasurement(type: "", registers: []),
            enclaveMeasurement: AttestationResponse(
                measurement: AttestationMeasurement(type: "", registers: [])
            ),
            securityVerified: false,
            steps: steps
        )
    }
}
