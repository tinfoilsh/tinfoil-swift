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
    case githubDigestFetchFailed(String)
    case attestationBundleFetchFailed(String)
    case sigstoreRootFetchFailed(String)
    case attestationVerificationFailed(String)
    case enclaveAttestationFailed(String)
    case digestMismatch(String)
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
    public let onCodeVerificationComplete: (StepResult) -> Void
    public let onRuntimeVerificationComplete: (StepResult) -> Void
    public let onSecurityCheckComplete: (StepResult) -> Void
    
    public init(
        onCodeVerificationComplete: @escaping (StepResult) -> Void = { _ in },
        onRuntimeVerificationComplete: @escaping (StepResult) -> Void = { _ in },
        onSecurityCheckComplete: @escaping (StepResult) -> Void = { _ in }
    ) {
        self.onCodeVerificationComplete = onCodeVerificationComplete
        self.onRuntimeVerificationComplete = onRuntimeVerificationComplete
        self.onSecurityCheckComplete = onSecurityCheckComplete
    }
}

/// Final verification result
public struct VerificationResult {
    public let codeDigest: String
    public let runtimeDigest: String
    public let isMatch: Bool
    public let publicKeyFP: String
}

/// A client for securely verifying code integrity through remote attestation
public class SecureClient {
    private let githubRepo: String
    private let enclaveURL: String
    private let callbacks: VerificationCallbacks
    
    /// Initialize a secure client with required configuration
    /// - Parameters:
    ///   - githubRepo: GitHub repository in the format "org/repo"
    ///   - enclaveURL: URL for the enclave attestation endpoint
    ///   - callbacks: Optional callbacks for verification progress
    public init(
        githubRepo: String,
        enclaveURL: String,
        callbacks: VerificationCallbacks = VerificationCallbacks()
    ) {
        self.githubRepo = githubRepo
        self.enclaveURL = enclaveURL
        self.callbacks = callbacks
    }
    
    /// Verifies the committed code and runtime binaries using remote attestation
    /// - Returns: A verification result or throws an error
    public func verify() async throws -> VerificationResult {
        // Get the full repo name
        let repo = githubRepo
        
        // STEP 1: Verify code with GitHub and Sigstore
        let codeDigest = try await verifyCodeWithGitHub(repo: repo)
        
        // STEP 2: Verify runtime with enclave attestation
        let (runtimeDigest, publicKeyFP) = try await verifyRuntimeWithEnclave()
        
        // STEP 3: Compare the digests
        let isMatch = codeDigest == runtimeDigest
        
        // Report security check result
        if isMatch {
            callbacks.onSecurityCheckComplete(.success(digest: "Digests match"))
        } else {
            let error = VerificationError.digestMismatch("Code digest does not match runtime digest")
            callbacks.onSecurityCheckComplete(.failure(error))
            throw error
        }
        
        return VerificationResult(
            codeDigest: codeDigest,
            runtimeDigest: runtimeDigest,
            isMatch: isMatch,
            publicKeyFP: publicKeyFP
        )
    }
    
    // MARK: - Private Methods
    
    private func verifyCodeWithGitHub(repo: String) async throws -> String {
        var error: NSError?
        
        do {
            // Fetch latest binary digest from GitHub
            let digest = TinfoilVerifier.GithubFetchLatestDigest(repo, &error)
            
            guard !digest.isEmpty else {
                let verificationError = VerificationError.githubDigestFetchFailed(error?.localizedDescription ?? "Unknown error")
                callbacks.onCodeVerificationComplete(.failure(verificationError))
                throw verificationError
            }
            
            // Fetch attestation bundle from GitHub
            guard let sigstoreBundle = TinfoilVerifier.GithubFetchAttestationBundle(repo, digest, &error) else {
                let verificationError = VerificationError.attestationBundleFetchFailed(error?.localizedDescription ?? "Unknown error")
                callbacks.onCodeVerificationComplete(.failure(verificationError))
                throw verificationError
            }
            
            // Fetch Sigstore root certificate
            guard let sigstoreRoot = TinfoilVerifier.SigstoreFetchTrustRoot(&error) else {
                let verificationError = VerificationError.sigstoreRootFetchFailed(error?.localizedDescription ?? "Unknown error")
                callbacks.onCodeVerificationComplete(.failure(verificationError))
                throw verificationError
            }
            
            // Verify the bundle from GitHub was stored on Sigstore
            guard let measurement = TinfoilVerifier.SigstoreVerifyAttestation(sigstoreRoot, sigstoreBundle, digest, repo, &error) else {
                let verificationError = VerificationError.attestationVerificationFailed(error?.localizedDescription ?? "Unknown error")
                callbacks.onCodeVerificationComplete(.failure(verificationError))
                throw verificationError
            }
            
            callbacks.onCodeVerificationComplete(.success(digest: digest))
            
            // Extract fingerprint from measurement
            guard let fingerprint = measurement.value(forKey: "fingerprint") as? String,
                  !fingerprint.isEmpty else {
                let verificationError = VerificationError.attestationVerificationFailed("Missing fingerprint in measurement")
                callbacks.onCodeVerificationComplete(.failure(verificationError))
                throw verificationError
            }
            
            return fingerprint
            
        } catch let verificationError as VerificationError {
            // Already reported above, just rethrow
            throw verificationError
        } catch {
            // Handle unexpected errors
            let wrappedError = VerificationError.unknown(error)
            callbacks.onCodeVerificationComplete(.failure(wrappedError))
            throw wrappedError
        }
    }
    
    private func verifyRuntimeWithEnclave() async throws -> (String, String) {
        var error: NSError?
        
        do {
            // Parse the enclave URL to extract the host
            let urlComponents: (url: URL, host: String, scheme: String, port: Int?)
            do {
                urlComponents = try URLHelpers.parseURL(enclaveURL)
            } catch {
                let verificationError = VerificationError.enclaveAttestationFailed("Invalid enclave URL: \(enclaveURL)")
                callbacks.onRuntimeVerificationComplete(.failure(verificationError))
                throw verificationError
            }
            
            // Fetch attestation from enclave using the host
            guard let enclaveAttestation = TinfoilVerifier.AttestationFetch(urlComponents.host, &error) else {
                let verificationError = VerificationError.enclaveAttestationFailed(error?.localizedDescription ?? "Failed to fetch attestation")
                callbacks.onRuntimeVerificationComplete(.failure(verificationError))
                throw verificationError
            }
            
            // Verify the attestation document
            let verification: AttestationVerification
            do {
                verification = try enclaveAttestation.verify()
            } catch {
                let verificationError = VerificationError.enclaveAttestationFailed(error.localizedDescription)
                callbacks.onRuntimeVerificationComplete(.failure(verificationError))
                throw verificationError
            }
            
            callbacks.onRuntimeVerificationComplete(.inProgress())
            
            // Extract fingerprint from verification result
            guard let measurementProperty = verification.value(forKey: "measurement") as? NSObject,
                  let fingerprint = measurementProperty.value(forKey: "fingerprint") as? String, // Fingerprint is the hash of all runtime measurements
                  !fingerprint.isEmpty else {
                let verificationError = VerificationError.enclaveAttestationFailed("Missing fingerprint in measurement")
                callbacks.onRuntimeVerificationComplete(.failure(verificationError))
                throw verificationError
            }

            // Extract the public key fingerprint
            guard let publicKey = verification.value(forKey: "publicKeyFP") as? String,
                  !publicKey.isEmpty else {
                let verificationError = VerificationError.enclaveAttestationFailed("Missing public key fingerprint")
                callbacks.onRuntimeVerificationComplete(.failure(verificationError))
                throw verificationError
            }

            // Report success
            callbacks.onRuntimeVerificationComplete(.success(digest: fingerprint))
            return (fingerprint, publicKey)
            
        } catch let verificationError as VerificationError {
            // Already reported above, just rethrow
            throw verificationError
        } catch {
            // Handle unexpected errors
            let wrappedError = VerificationError.unknown(error)
            callbacks.onRuntimeVerificationComplete(.failure(wrappedError))
            throw wrappedError
        }
    }
}
