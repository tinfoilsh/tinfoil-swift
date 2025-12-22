import Foundation
import CryptoKit
import Security

/// Callback type for verification events
/// - Parameter verificationDocument: The verification document from attestation
public typealias VerificationCallback = @Sendable (VerificationDocument?) -> Void

/// A URLSession delegate that performs certificate pinning and extraction
public class CertificatePinningDelegate: NSObject, URLSessionDelegate {
    private let expectedFingerprint: String

    public init(expectedFingerprint: String) {
        self.expectedFingerprint = expectedFingerprint
        super.init()
    }
    
    public func urlSession(
        _ session: URLSession, 
        didReceive challenge: URLAuthenticationChallenge, 
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Ensure this is a server trust challenge
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Use the modern API to get certificate chain
        guard let certificateChain = SecTrustCopyCertificateChain(serverTrust),
              CFArrayGetCount(certificateChain) > 0,
              let serverCertificate = CFArrayGetValueAtIndex(certificateChain, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let certificate = unsafeBitCast(serverCertificate, to: SecCertificate.self)

        guard let publicKey = SecCertificateCopyKey(certificate),
              let rawKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard let spkiData = Self.convertToSPKI(rawKeyData: rawKeyData) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let serverPublicKeyFingerprint = SHA256.hash(data: spkiData)
                                               .map { String(format: "%02x", $0) }
                                               .joined()

        let verificationPassed = serverPublicKeyFingerprint == expectedFingerprint

        if verificationPassed {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// Converts raw EC key data to SPKI (SubjectPublicKeyInfo) DER format
    ///
    /// This method attempts to parse the raw key data as different elliptic curves
    /// in order of likelihood: P-384, P-256, then P-521. This provides flexibility
    /// to support different certificate types without hardcoding a specific curve.
    ///
    /// - Parameter rawKeyData: Raw X9.63 key bytes from SecKeyCopyExternalRepresentation
    /// - Returns: SPKI DER-encoded data if successful, or nil if the key type is unsupported
    private static func convertToSPKI(rawKeyData: Data) -> Data? {
        if let p384Key = try? P384.Signing.PublicKey(x963Representation: rawKeyData) {
            return p384Key.derRepresentation
        }

        if let p256Key = try? P256.Signing.PublicKey(x963Representation: rawKeyData) {
            return p256Key.derRepresentation
        }

        if let p521Key = try? P521.Signing.PublicKey(x963Representation: rawKeyData) {
            return p521Key.derRepresentation
        }

        return nil
    }
}

/// Factory for creating URLSessions with certificate pinning and extraction
public class SecureURLSessionFactory {
    
    /// Creates a URLSession with certificate pinning and extraction
    /// - Parameters:
    ///   - expectedFingerprint: The expected certificate fingerprint
    /// - Returns: A configured URLSession
    public static func createSession(expectedFingerprint: String) -> URLSession {
        let delegate = CertificatePinningDelegate(expectedFingerprint: expectedFingerprint)
        
        let configuration = URLSessionConfiguration.default
        // Disable caching for security
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData

        // Keep connections alive longer to avoid frequent reconnects
        configuration.shouldUseExtendedBackgroundIdleMode = true

        // Use a specific operation queue for delegate callbacks
        // Allow concurrent operations since delegate methods are thread-safe
        // (HTTP/2 handles multiplexing over a single connection)
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = OperationQueue.defaultMaxConcurrentOperationCount

        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: delegateQueue)
    }
} 
