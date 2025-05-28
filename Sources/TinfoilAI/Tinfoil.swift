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
    ///   - parsingOptions: Parsing options for handling different providers.
    ///   - nonblockingVerification: Optional callback for non-blocking certificate verification results
    public init(
        apiKey: String? = nil,
        githubRepo: String,
        enclaveURL: String,
        parsingOptions: ParsingOptions = .relaxed,
        nonblockingVerification: NonblockingVerification? = nil
    ) async throws {
        // Get API key from parameter or environment
        let finalApiKey = apiKey ?? ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        guard let finalApiKey = finalApiKey else {
            throw TinfoilError.missingAPIKey
        }
        
        do {
            // Validate enclave URL by attempting to parse it
            _ = try URLHelpers.parseURL(enclaveURL)
        } catch {
            throw TinfoilError.invalidConfiguration("Invalid enclave URL: \(enclaveURL)")
        }
        
        // Parse and validate the GitHub repo string
        guard let (_, _) = TinfoilAI.parseGitHubRepo(githubRepo) else {
            throw TinfoilError.invalidConfiguration(
                "Invalid GitHub repository format. Expected 'org/repo', got '\(githubRepo)'"
            )
        }
        
        // First verify the enclave
        let verifier = SecureClient(
            githubRepo: githubRepo,
            enclaveURL: enclaveURL,
            callbacks: VerificationCallbacks()
        )
        
        // get the verification result + cert fingerprint
        let verificationResult = try await verifier.verify()
        
        // create the tinfoil client
        let tinfoilClient = try TinfoilClient.create(
            apiKey: finalApiKey,
            enclaveURL: enclaveURL,
            expectedFingerprint: verificationResult.publicKeyFP,
            parsingOptions: parsingOptions,
            nonblockingVerification: nonblockingVerification
        )
        
        self.tinfoilClient = tinfoilClient
        self.client = tinfoilClient.underlyingClient
    }
    
    deinit {
        // Clean up resources
        self.tinfoilClient?.shutdown()
    }
    
    /// Parses a GitHub repository string into org and repo components
    /// - Parameter githubRepo: Repository string in format "org/repo"
    /// - Returns: Tuple of (org, repo) if valid, nil otherwise
    private static func parseGitHubRepo(_ githubRepo: String) -> (org: String, repo: String)? {
        let components = githubRepo.split(separator: "/")
        guard components.count == 2,
              !components[0].isEmpty,
              !components[1].isEmpty else {
            return nil
        }
        return (org: String(components[0]), repo: String(components[1]))
    }
}

/// Errors that can occur when using the Tinfoil client
public enum TinfoilError: Error {
    case missingAPIKey
    case invalidConfiguration(String)
    case connectionError(String)
} 