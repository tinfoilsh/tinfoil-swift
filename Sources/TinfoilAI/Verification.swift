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
    public let hpkePublicKey: String
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
    
    /// Initialize a secure client with required configuration
    /// - Parameters:
    ///   - githubRepo: GitHub repository in the format "org/repo"
    ///   - enclaveURL: URL for the enclave attestation endpoint
    ///   - callbacks: Optional callbacks for verification progress
    public init(
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        enclaveURL: String = TinfoilConstants.defaultEnclaveURL,
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
    
    /// Verifies the committed code and runtime binaries using remote attestation
    /// - Returns: The ground truth containing all verification results
    public func verify() async throws -> GroundTruth {
        callbacks.onVerificationStart()
        
        do {
            // Parse the enclave URL to extract the host
            let urlComponents = try URLHelpers.parseURL(enclaveURL)
            
            // Create a new TinfoilVerifier secure client
            guard let client = TinfoilVerifier.ClientNewSecureClient(urlComponents.host, githubRepo) else {
                let error = VerificationError.verificationFailed("Failed to create secure client")
                callbacks.onVerificationComplete(.failure(error))
                throw error
            }
            
            // Run verification
            do {
                _ = try client.verify()
            } catch {
                let verificationError = VerificationError.verificationFailed("Verification failed: \(error.localizedDescription)")
                callbacks.onVerificationComplete(.failure(verificationError))
                throw verificationError
            }
            
            // Get the ground truth as JSON string from the client
            var jsonError: NSError?
            let jsonString = client.groundTruthJSON(&jsonError)

            if let error = jsonError {
                let verificationError = VerificationError.jsonDecodingFailed(error.localizedDescription)
                callbacks.onVerificationComplete(.failure(verificationError))
                throw verificationError
            }

            guard let jsonData = jsonString.data(using: .utf8) else {
                let verificationError = VerificationError.jsonDecodingFailed("Failed to convert JSON string to data")
                callbacks.onVerificationComplete(.failure(verificationError))
                throw verificationError
            }
            
            // Decode the ground truth JSON
            let decoder = JSONDecoder()
            do {
                let groundTruth = try decoder.decode(GroundTruth.self, from: jsonData)
                self.groundTruth = groundTruth
                callbacks.onVerificationComplete(.success(groundTruth))
                return groundTruth
            } catch {
                let decodingError = VerificationError.jsonDecodingFailed(error.localizedDescription)
                callbacks.onVerificationComplete(.failure(decodingError))
                throw decodingError
            }
            
        } catch let verificationError as VerificationError {
            throw verificationError
        } catch {
            let wrappedError = VerificationError.unknown(error)
            callbacks.onVerificationComplete(.failure(wrappedError))
            throw wrappedError
        }
    }
}
