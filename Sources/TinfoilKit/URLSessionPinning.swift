import Foundation
import CryptoKit

/// Custom error type for certificate verification failures
public enum CertificateVerificationError: Error {
    case fingerprintMismatch(String, String)
    case noCertificate
    case verificationFailed(Error)
}

/// A URLSession delegate that performs certificate pinning
public class CertificatePinningDelegate: NSObject, URLSessionDelegate {
    private let expectedFingerprint: String
    
    public init(expectedFingerprint: String) {
        self.expectedFingerprint = expectedFingerprint
        super.init()
    }
    
    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Ensure this is a server trust challenge
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            // If not, reject the challenge
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get the server's certificate data (we only check the leaf certificate)
        guard let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get the certificate data
        let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data
        
        // Calculate the fingerprint
        let serverFingerprint = SHA256.hash(data: serverCertificateData).compactMap {
            String(format: "%02x", $0)
        }.joined()
        
        // Verify that the fingerprints match
        if serverFingerprint == expectedFingerprint {
            // If they match, accept the server's certificate
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            // If they don't match, reject the challenge
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

/// Factory for creating URLSessions with certificate pinning
public class SecureURLSessionFactory {
    
    /// Creates a URLSession with certificate pinning
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