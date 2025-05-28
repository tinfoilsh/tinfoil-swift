import Foundation
import OpenAI

/// A secure wrapper for OpenAI client that uses certificate pinning
/// to validate the enclave connection.
public class TinfoilClient {
    private let client: OpenAI
    private let urlSession: URLSession
    
    private init(client: OpenAI, urlSession: URLSession) {
        self.client = client
        self.urlSession = urlSession
    }
    
    public static func create(
        apiKey: String,
        enclaveURL: String,
        expectedFingerprint: String,
        parsingOptions: OpenAI.Configuration.ParsingOptions = .relaxed
    ) throws -> TinfoilClient {
        // Create the secure URLSession with certificate pinning and extraction
        let urlSession = SecureURLSessionFactory.createSession(
            expectedFingerprint: expectedFingerprint
        )
        
        // Parse the enclave URL
        guard let url = URL(string: enclaveURL),
              let host = url.host else {
            throw NSError(domain: "sh.tinfoil.secure-urlsession", 
                          code: 1001, 
                          userInfo: [NSLocalizedDescriptionKey: "Invalid URL: \(enclaveURL)"])
        }
        
        // Extract components from URL
        let scheme = url.scheme ?? "https"
        let port = url.port
        
        // Build host string with port if needed
        let hostWithPort = port != nil ? "\(host):\(port!)" : host
        
        // Create OpenAI configuration with custom host, session, and parsing options
        // Using .relaxed parsing to support non OpenAI models
        let configuration = OpenAI.Configuration(
            token: apiKey,
            host: hostWithPort,
            scheme: scheme,
            parsingOptions: parsingOptions
        )
        
        let openAIClient = OpenAI(
            configuration: configuration,
            session: urlSession
        )
        
        // Create and return the secure wrapper
        return TinfoilClient(
            client: openAIClient,
            urlSession: urlSession
        )
    }
    
    /// Forwards requests to the underlying OpenAI client
    public var underlyingClient: OpenAI {
        return self.client
    }
    
    /// Shuts down the client
    public func shutdown() {
        // Cancel all tasks and invalidate the URLSession
        self.urlSession.invalidateAndCancel()
    }
} 