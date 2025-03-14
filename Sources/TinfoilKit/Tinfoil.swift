import Foundation
import OpenAIKit

/// Main entry point for the Tinfoil secure AI client library
public final class TinfoilAI {
    public let client: OpenAIKit.Client
    private let secureOpenAIClient: SecureOpenAIClient?
    
    /// Creates a new secure OpenAI client
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from OPENAI_API_KEY environment variable
    ///   - githubOrg: GitHub organization name for verification
    ///   - githubRepo: GitHub repository name for verification
    ///   - enclaveURL: URL for the enclave attestation endpoint
    public init(
        apiKey: String? = nil,
        githubOrg: String,
        githubRepo: String,
        enclaveURL: String
    ) async throws {
        // Get API key from parameter or environment
        let finalApiKey = apiKey ?? ProcessInfo.processInfo.environment["OPENAI_API_KEY"]
        guard let finalApiKey = finalApiKey else {
            throw TinfoilError.missingAPIKey
        }
        
        // Validate enclave URL
        guard URL(string: enclaveURL) != nil else {
            throw TinfoilError.invalidConfiguration("Invalid enclave URL: \(enclaveURL)")
        }
        
        // First verify the enclave
        let verifier = SecureClient(
            githubOrg: githubOrg,
            githubRepo: githubRepo,
            enclaveURL: enclaveURL,
            callbacks: VerificationCallbacks()
        )
        
        let verificationResult = try await verifier.verify()
        
        // Create secure OpenAI client with certificate fingerprint verification
        let secureClient = try SecureOpenAIClient.create(
            apiKey: finalApiKey,
            enclaveURL: enclaveURL,
            expectedFingerprint: verificationResult.certFingerprint
        )
        
        self.secureOpenAIClient = secureClient
        self.client = secureClient.underlyingClient
    }
    
    deinit {
        // Clean up resources
        self.secureOpenAIClient?.shutdown()
    }
    
    /// Test the connection to the enclave
    /// - Returns: A result with success message or detailed error
    public func testConnection() async -> Result<String, Error> {
        guard let secureClient = self.secureOpenAIClient else {
            return .failure(TinfoilError.invalidConfiguration("Secure client not initialized"))
        }
        
        return await secureClient.testConnection()
    }
}

/// Errors that can occur when using the Tinfoil client
public enum TinfoilError: Error {
    case missingAPIKey
    case invalidConfiguration(String)
    case connectionError(String)
} 