import Foundation
import OpenAI

/// Main entry point for the Tinfoil client library
public enum TinfoilAI {
    
    /// Creates a new secure OpenAI client configured for communication with a Tinfoil enclave
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from TINFOIL_API_KEY environment variable
    ///   - enclaveURL: Optional URL of the Tinfoil enclave. If not provided, will fetch from router API
    ///   - githubRepo: GitHub repository containing the enclave config
    ///   - parsingOptions: Parsing options for handling different providers.
    ///   - nonblockingVerification: Optional callback for non-blocking certificate verification results
    /// - Returns: An OpenAI client configured for secure communication with the Tinfoil enclave
    public static func create(
        apiKey: String? = nil,
        enclaveURL: String? = nil,
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        parsingOptions: ParsingOptions = .relaxed,
        nonblockingVerification: NonblockingVerification? = nil
    ) async throws -> OpenAI {
        // Get API key from parameter or environment
        let finalApiKey = apiKey ?? ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        guard let finalApiKey = finalApiKey else {
            throw TinfoilError.missingAPIKey
        }

        // Determine the enclave URL - fetch from router if not provided
        let finalEnclaveURL: String
        if let providedURL = enclaveURL {
            finalEnclaveURL = providedURL
        } else {
            // Fetch router address from ATC API
            let routerAddress = try await RouterManager.fetchRouter()
            finalEnclaveURL = "https://\(routerAddress)"
        }

        // Create SecureClient with enclave URL and GitHub repo
        let verifier = SecureClient(
            githubRepo: githubRepo,
            enclaveURL: finalEnclaveURL,
            callbacks: VerificationCallbacks()
        )
        
        // get the verification result + cert fingerprint
        let groundTruth = try await verifier.verify()
        
        // create the tinfoil client
        let tinfoilClient = try TinfoilClient.create(
            apiKey: finalApiKey,
            enclaveURL: finalEnclaveURL,
            expectedFingerprint: groundTruth.tlsPublicKey,
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
public enum TinfoilError: Error, Equatable {
    case missingAPIKey
    case invalidConfiguration(String)
    case connectionError(String)
} 