import Foundation
import OpenAI

/// SSL delegate for streaming certificate pinning
final class StreamingSSLDelegate: SSLDelegateProtocol {
    private let expectedFingerprint: String
    private let nonblockingVerification: NonblockingVerification?
    
    init(expectedFingerprint: String, nonblockingVerification: NonblockingVerification? = nil) {
        self.expectedFingerprint = expectedFingerprint
        self.nonblockingVerification = nonblockingVerification
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Reuse the same certificate validation logic as CertificatePinningDelegate
        let delegate = CertificatePinningDelegate(
            expectedFingerprint: expectedFingerprint, 
            nonblockingVerification: nonblockingVerification
        )
        delegate.urlSession(session, didReceive: challenge, completionHandler: completionHandler)
    }
}

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
        parsingOptions: ParsingOptions = .relaxed,
        nonblockingVerification: NonblockingVerification? = nil
    ) throws -> TinfoilClient {
        // Create the secure URLSession with certificate pinning and extraction
        let urlSession = SecureURLSessionFactory.createSession(
            expectedFingerprint: expectedFingerprint,
            nonblockingVerification: nonblockingVerification
        )
        
        // Create SSL delegate for streaming certificate pinning
        let sslDelegate = StreamingSSLDelegate(
            expectedFingerprint: expectedFingerprint,
            nonblockingVerification: nonblockingVerification
        )
        
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
            // cert pinning for non-streaming requests
            session: urlSession, 
            middlewares: [],
            // cert pinning for streaming requests.
            sslStreamingDelegate: sslDelegate 
        )
        
        // Create and return the secure wrapper
        return TinfoilClient(client: openAIClient, urlSession: urlSession)
    }
    
    /// Forwards requests to the underlying OpenAI client
    public var underlyingClient: OpenAI {
        return self.client
    }
    
    /// Cleans up resources and invalidates the URLSession
    public func shutdown() {
        urlSession.invalidateAndCancel()
    }
} 