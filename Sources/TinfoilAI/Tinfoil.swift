import Foundation
import OpenAI

/// Main entry point for the Tinfoil client library
public enum TinfoilAI {
    
    /// Creates a new secure OpenAI client configured for communication with a Tinfoil enclave
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from TINFOIL_API_KEY environment variable

    ///   - parsingOptions: Parsing options for handling different providers.
    ///   - nonblockingVerification: Optional callback for non-blocking certificate verification results
    /// - Returns: An OpenAI client configured for secure communication with the Tinfoil enclave
    public static func create(
        apiKey: String? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        nonblockingVerification: NonblockingVerification? = nil
    ) async throws -> OpenAI {
        // Get API key from parameter or environment
        let finalApiKey = apiKey ?? ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        guard let finalApiKey = finalApiKey else {
            throw TinfoilError.missingAPIKey
        }
        
        
        // Create SecureClient with no parameters since Go function is now NewSecureClient()
        let verifier = SecureClient()
        
        // get the verification result + cert fingerprint
        let verificationResult = try await verifier.verify()
        
        // create the tinfoil client
        let tinfoilClient = try TinfoilClient.create(
            apiKey: finalApiKey,
            expectedFingerprint: verificationResult.publicKeyFP,
            parsingOptions: parsingOptions,
            nonblockingVerification: nonblockingVerification
        )
        
        // Return the underlying OpenAI client directly
        // Note: The URLSession with certificate pinning is held by the OpenAI client
        // and will be cleaned up when the OpenAI client is deallocated
        return tinfoilClient.underlyingClient
    }
    

}

/// Errors that can occur when using the Tinfoil client
public enum TinfoilError: Error {
    case missingAPIKey
    case invalidConfiguration(String)
    case connectionError(String)
} 