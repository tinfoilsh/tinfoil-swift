import Foundation
import OpenAI

/// Main entry point for the Tinfoil client library
public enum TinfoilAI {
    
    /// Creates a new OpenAI client configured for communication with a Tinfoil enclave
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from TINFOIL_API_KEY environment variable
    ///   - enclaveURL: Optional URL of the Tinfoil enclave. If not provided, will fetch from router API
    ///   - githubRepo: GitHub repository containing the enclave config
    ///   - parsingOptions: Parsing options for handling different providers.
    ///   - onVerification: Optional callback for verification results (both attestation and TLS)
    /// - Returns: An OpenAI client configured for secure communication
    public static func create(
        apiKey: String? = nil,
        enclaveURL: String? = nil,
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        parsingOptions: ParsingOptions = .relaxed,
        onVerification: VerificationCallback? = nil
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
            enclaveURL: finalEnclaveURL
        )

        // get the verification result + cert fingerprint
        do {
            let groundTruth = try await verifier.verify()

            // Get the verification document
            let verificationDocument = verifier.getVerificationDocument()

            // Call the verification callback with the attestation result
            onVerification?(verificationDocument)

            // create the tinfoil client
            let tinfoilClient = try TinfoilClient.create(
                apiKey: finalApiKey,
                enclaveURL: finalEnclaveURL,
                expectedFingerprint: groundTruth.tlsPublicKey,
                parsingOptions: parsingOptions
            )

            // Return the underlying OpenAI client directly
            return tinfoilClient.underlyingClient
        } catch {
            // Verification failed - call the callback with the failure document (if available)
            let verificationDocument = verifier.getVerificationDocument()
            onVerification?(verificationDocument)

            // Re-throw the error
            throw error
        }
    }
    

}

/// Errors that can occur when using the Tinfoil client
public enum TinfoilError: Error, Equatable {
    case missingAPIKey
    case invalidConfiguration(String)
    case connectionError(String)
} 