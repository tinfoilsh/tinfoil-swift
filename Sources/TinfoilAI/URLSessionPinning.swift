import Foundation
import CryptoKit
import Security

/// Custom error type for certificate verification failures
public enum CertificateVerificationError: Error {
    case fingerprintMismatch(String, String)
    case noCertificate
    case verificationFailed(Error)
}

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

        // Extract certificate data if needed for further processing
        let certificateData = SecCertificateCopyData(certificate)
        let certificateLength = CFDataGetLength(certificateData)
        
        guard let publicKey = SecCertificateCopyKey(certificate),
              let x963Data  = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Build P-384 key from the raw ANSI X9.63 bytes
        guard let p384Public = try? P384.Signing.PublicKey(x963Representation: x963Data) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let spkiData = p384Public.derRepresentation

        let serverPublicKeyFingerprint = SHA256.hash(data: spkiData)
                                               .map { String(format: "%02x", $0) }
                                               .joined()

        if serverPublicKeyFingerprint == expectedFingerprint {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

/// Factory for creating URLSessions with certificate pinning and extraction
public class SecureURLSessionFactory {
    
    /// Creates a URLSession with certificate pinning and extraction
    public static func createSession(expectedFingerprint: String) -> URLSession {
        let delegate = CertificatePinningDelegate(expectedFingerprint: expectedFingerprint)
        
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
