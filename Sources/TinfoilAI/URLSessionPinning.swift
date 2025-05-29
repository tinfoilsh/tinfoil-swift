import Foundation
import CryptoKit
import Security

/// Callback type for non-blocking verification results
/// - Parameter verificationPassed: true if certificate pinning verification passed, false otherwise
public typealias NonblockingVerification = @Sendable (Bool) -> Void

/// Custom error type for certificate verification failures
public enum CertificateVerificationError: Error {
    case fingerprintMismatch(String, String)
    case noCertificate
    case verificationFailed(Error)
}

/// A URLSession delegate that performs certificate pinning and extraction
public class CertificatePinningDelegate: NSObject, URLSessionDelegate {
    private let expectedFingerprint: String
    private let nonblockingVerification: NonblockingVerification?
    
    public init(expectedFingerprint: String, nonblockingVerification: NonblockingVerification? = nil) {
        self.expectedFingerprint = expectedFingerprint
        self.nonblockingVerification = nonblockingVerification
        super.init()
    }
    
    public func urlSession(
        _ session: URLSession, 
        didReceive challenge: URLAuthenticationChallenge, 
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Ensure this is a server trust challenge
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            nonblockingVerification?(false)
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Use the modern API to get certificate chain
        guard let certificateChain = SecTrustCopyCertificateChain(serverTrust),
              CFArrayGetCount(certificateChain) > 0,
              let serverCertificate = CFArrayGetValueAtIndex(certificateChain, 0) else {
            nonblockingVerification?(false)
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let certificate = unsafeBitCast(serverCertificate, to: SecCertificate.self)

        
        guard let publicKey = SecCertificateCopyKey(certificate),
              let x963Data  = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            nonblockingVerification?(false)
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Build P-384 key from the raw ANSI X9.63 bytes
        guard let p384Public = try? P384.Signing.PublicKey(x963Representation: x963Data) else {
            nonblockingVerification?(false)
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let spkiData = p384Public.derRepresentation

        let serverPublicKeyFingerprint = SHA256.hash(data: spkiData)
                                               .map { String(format: "%02x", $0) }
                                               .joined()

        let verificationPassed = serverPublicKeyFingerprint == expectedFingerprint
        
        // Call the non-blocking verification callback if provided
        nonblockingVerification?(verificationPassed)
        
        if verificationPassed {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            // If non-blocking verification is enabled, proceed with the connection even on mismatch
            if nonblockingVerification != nil {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
            } else {
                // Default behavior: cancel on mismatch
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }
    }
}

/// Factory for creating URLSessions with certificate pinning and extraction
public class SecureURLSessionFactory {
    
    /// Creates a URLSession with certificate pinning and extraction
    /// - Parameters:
    ///   - expectedFingerprint: The expected certificate fingerprint
    ///   - nonblockingVerification: Optional callback for non-blocking verification results
    /// - Returns: A configured URLSession
    public static func createSession(
        expectedFingerprint: String, 
        nonblockingVerification: NonblockingVerification? = nil
    ) -> URLSession {
        let delegate = CertificatePinningDelegate(
            expectedFingerprint: expectedFingerprint,
            nonblockingVerification: nonblockingVerification
        )
        
        let configuration = URLSessionConfiguration.default
        // Disable caching for security
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        
        // Use a specific operation queue for delegate callbacks to ensure thread safety
        let delegateQueue = OperationQueue()
        delegateQueue.maxConcurrentOperationCount = 1 // Serial queue for thread safety
        
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: delegateQueue)
    }
} 
