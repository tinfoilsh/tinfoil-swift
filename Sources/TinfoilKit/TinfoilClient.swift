import Foundation
import OpenAIKit

/// A secure wrapper for OpenAI-Kit client that uses certificate pinning
/// to validate the enclave connection.
public class TinfoilClient {
    private let client: OpenAIKit.Client
    private let urlSession: URLSession
    
    private init(client: OpenAIKit.Client, urlSession: URLSession) {
        self.client = client
        self.urlSession = urlSession
    }
    
    public static func create(
        apiKey: String,
        enclaveURL: String,
        expectedFingerprint: String
    ) throws -> TinfoilClient {
        // Create the secure URLSession with certificate pinning
        let urlSession = SecureURLSessionFactory.createSession(
            expectedFingerprint: expectedFingerprint
        )
        
        // Parse the URL components using the dedicated parser
        let urlComponents = URLParser.parse(url: enclaveURL)
    
        // Construct the base URL string
        let apiBaseURLString = "https://\(urlComponents.finalHost)\(urlComponents.pathPrefix)"
        
        // Additional verification to ensure we have a valid URL
        guard URL(string: apiBaseURLString) != nil else {
            throw NSError(domain: "sh.tinfoil.secure-urlsession", 
                          code: 1001, 
                          userInfo: [NSLocalizedDescriptionKey: "Invalid URL generated: \(apiBaseURLString)"])
        }
        
        // Create API configuration
        let api = OpenAIKit.API(
            scheme: .https,
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
        return TinfoilClient(
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
} 