import Foundation
import OpenAI

/// Main entry point for the Tinfoil client library
public final class TinfoilAI {
    public let client: OpenAI
    private let tinfoilClient: TinfoilClient?
    
    /// Creates a new Tinfoil client wrapping the OpenAI client
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from TINFOIL_API_KEY environment variable
    ///   - githubRepo: GitHub repository in the format "org/repo"
    ///   - enclaveURL: URL for the enclave attestation endpoint
    public init(
        apiKey: String? = nil,
        githubRepo: String,
        enclaveURL: String
    ) async throws {
        // Get API key from parameter or environment
        let finalApiKey = apiKey ?? ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        guard let finalApiKey = finalApiKey else {
            throw TinfoilError.missingAPIKey
        }
        
        // Validate enclave URL
        guard URL(string: enclaveURL) != nil else {
            throw TinfoilError.invalidConfiguration("Invalid enclave URL: \(enclaveURL)")
        }
        
        // Parse the GitHub repo string to extract org and repo
        let repoComponents = githubRepo.split(separator: "/")
        guard repoComponents.count == 2, !repoComponents[0].isEmpty, !repoComponents[1].isEmpty else {
            throw TinfoilError.invalidConfiguration("Invalid GitHub repository format. Expected 'org/repo' but got '\(githubRepo)'")
        }
        
        // First verify the enclave
        let verifier = SecureClient(
            githubRepo: githubRepo,
            enclaveURL: enclaveURL,
            callbacks: VerificationCallbacks()
        )
        
        let verificationResult = try await verifier.verify()
        
        let tinfoilClient = try TinfoilClient.create(
            apiKey: finalApiKey,
            enclaveURL: enclaveURL,
            expectedFingerprint: verificationResult.publicKeyFP
        )
        
        self.tinfoilClient = tinfoilClient
        self.client = tinfoilClient.underlyingClient
    }
    
    deinit {
        // Clean up resources
        self.tinfoilClient?.shutdown()
    }
}

/// Errors that can occur when using the Tinfoil client
public enum TinfoilError: Error {
    case missingAPIKey
    case invalidConfiguration(String)
    case connectionError(String)
} 