import Foundation
import OpenAI

/// SSL delegate for streaming certificate pinning
final class StreamingSSLDelegate: SSLDelegateProtocol {
    private let expectedFingerprint: String
    
    init(expectedFingerprint: String) {
        self.expectedFingerprint = expectedFingerprint
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Reuse the same certificate validation logic as CertificatePinningDelegate
        let delegate = CertificatePinningDelegate(expectedFingerprint: expectedFingerprint)
        delegate.urlSession(session, didReceive: challenge, completionHandler: completionHandler)
    }
}

/// A secure wrapper for OpenAI client that uses certificate pinning
/// to validate the enclave connection.
public class TinfoilClient {
    private let client: OpenAI
    
    private init(client: OpenAI) {
        self.client = client
    }
    
    public static func create(
        apiKey: String,
        enclaveURL: String,
        expectedFingerprint: String,
        parsingOptions: ParsingOptions = .relaxed
    ) throws -> TinfoilClient {
        // Create the secure URLSession with certificate pinning and extraction
        let urlSession = SecureURLSessionFactory.createSession(
            expectedFingerprint: expectedFingerprint
        )
        
        // Create SSL delegate for streaming certificate pinning
        let sslDelegate = StreamingSSLDelegate(expectedFingerprint: expectedFingerprint)
        
        // Parse the enclave URL
        let urlComponents = try URLHelpers.parseURL(enclaveURL)
        
        // Build host string with port if needed
        let hostWithPort = URLHelpers.buildHostWithPort(host: urlComponents.host, port: urlComponents.port)
        
        // Create OpenAI configuration with custom host, session, and parsing options
        // Using .relaxed parsing to support non OpenAI models.
        // See https://github.com/MacPaw/OpenAI?tab=readme-ov-file#support-for-other-providers
        // for info on the .relaxed parsing option.
        let configuration = OpenAI.Configuration(
            token: apiKey,
            host: hostWithPort,
            scheme: urlComponents.scheme,
            parsingOptions: parsingOptions
        )
        
        let openAIClient = OpenAI(
            configuration: configuration,
            middlewares: [],
            // cert pinning for non-streaming requests
            session: urlSession, 
            // cert pinning for streaming requests.
            sslStreamingDelegate: sslDelegate 
        )
        
        // Create and return the secure wrapper
        return TinfoilClient(
            client: openAIClient
        )
    }
    
    /// Forwards requests to the underlying OpenAI client
    public var underlyingClient: OpenAI {
        return self.client
    }
} 