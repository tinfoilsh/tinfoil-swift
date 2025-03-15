import Foundation
import OpenAIKit

/// A secure wrapper for OpenAIKit.Client that uses certificate pinning
public class SecureOpenAIClient {
    private let client: OpenAIKit.Client
    private let urlSession: URLSession
    
    private init(client: OpenAIKit.Client, urlSession: URLSession) {
        self.client = client
        self.urlSession = urlSession
    }
    
    /// Creates a new secure OpenAI client with certificate pinning
    public static func create(
        apiKey: String,
        enclaveURL: String,
        expectedFingerprint: String
    ) throws -> SecureOpenAIClient {
        // Create a logger
        let logger = PinningLogger(label: "com.tinfoil.secure-urlsession")
        
        // Create the secure URLSession with certificate pinning
        let urlSession = SecureURLSessionFactory.createSession(
            expectedFingerprint: expectedFingerprint,
            logger: logger
        )
        
        // Parse the URL components using the dedicated parser
        let urlComponents = OpenAIURLParser.parse(url: enclaveURL, logger: logger)
        
        // Create custom API configuration with the parsed URL components
        let apiScheme: OpenAIKit.API.Scheme = urlComponents.scheme == "https" ? .https : .http
        
        // Log API configuration details
        logger.debug("Creating OpenAIKit.Client with API configuration:")
        logger.debug("- Scheme: \(urlComponents.scheme)")
        logger.debug("- Host: \(urlComponents.finalHost)")
        logger.debug("- Path prefix: \(urlComponents.pathPrefix)")
        logger.debug("- API key length: \(apiKey.count) characters")
        
        // Log the expected API base URL for debugging
        let apiBaseURLString: String
        if urlComponents.pathPrefix.isEmpty {
            apiBaseURLString = "\(urlComponents.scheme)://\(urlComponents.finalHost)"
            logger.debug("- Expected API base URL: \(apiBaseURLString) (no path prefix)")
        } else {
            apiBaseURLString = "\(urlComponents.scheme)://\(urlComponents.finalHost)/\(urlComponents.pathPrefix)"
            logger.debug("- Expected API base URL: \(apiBaseURLString)")
        }
        
        // Additional verification to ensure we have a valid URL
        guard URL(string: apiBaseURLString) != nil else {
            logger.error("Invalid URL generated: \(apiBaseURLString)")
            throw NSError(domain: "com.tinfoil.secure-urlsession", 
                          code: 1001, 
                          userInfo: [NSLocalizedDescriptionKey: "Invalid URL generated: \(apiBaseURLString)"])
        }
        
        // Create API configuration
        let api = OpenAIKit.API(
            scheme: apiScheme,
            host: urlComponents.finalHost,
            pathPrefix: urlComponents.pathPrefix
        )
        
        // Create client configuration with custom API
        let configuration = OpenAIKit.Configuration(
            apiKey: apiKey,
            organization: nil,
            api: api
        )
        
        let openAIClient = OpenAIKit.Client(session: urlSession, configuration: configuration)
        
        // Create and return the secure wrapper
        return SecureOpenAIClient(
            client: openAIClient,
            urlSession: urlSession
        )
    }
    
    /// Forwards requests to the underlying OpenAIKit.Client
    public var underlyingClient: OpenAIKit.Client {
        return self.client
    }
    
    /// Shuts down the client
    public func shutdown() {
        // Cancel all tasks and invalidate the URLSession
        self.urlSession.invalidateAndCancel()
    }
    
    /// Test the connection by fetching models (for debugging purposes)
    public func testConnection() async -> Result<String, Error> {
        do {
            // Try to make a simple request to list models
            let models = try await self.client.models.list()
            return .success("Successfully connected. Found \(models.count) models.")
        } catch {
            return .failure(error)
        }
    }
} 