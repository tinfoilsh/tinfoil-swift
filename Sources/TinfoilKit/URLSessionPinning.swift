import Foundation
import CryptoKit

/// Custom error type for certificate verification failures
public enum CertificateVerificationError: Error {
    case fingerprintMismatch(String, String)
    case noCertificate
    case verificationFailed(Error)
}

/// A lightweight logger for URLSession pinning
public class PinningLogger {
    public enum Level {
        case debug, info, warning, error
    }
    
    private let label: String
    
    public init(label: String) {
        self.label = label
    }
    
    public func log(_ level: Level, _ message: String) {
        let levelString: String
        switch level {
        case .debug: levelString = "DEBUG"
        case .info: levelString = "INFO"
        case .warning: levelString = "WARNING"
        case .error: levelString = "ERROR"
        }
        
        print("[\(levelString)] [\(label)] \(message)")
    }
    
    public func debug(_ message: String) {
        log(.debug, message)
    }
    
    public func info(_ message: String) {
        log(.info, message)
    }
    
    public func warning(_ message: String) {
        log(.warning, message)
    }
    
    public func error(_ message: String) {
        log(.error, message)
    }
}

/// A URLSession delegate that performs certificate pinning
public class CertificatePinningDelegate: NSObject, URLSessionDelegate {
    private let expectedFingerprint: String
    private let logger: PinningLogger?
    
    public init(expectedFingerprint: String, logger: PinningLogger? = nil) {
        self.expectedFingerprint = expectedFingerprint
        self.logger = logger
        super.init()
    }
    
    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Ensure this is a server trust challenge
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            logger?.warning("Not a server trust challenge")
            // If not, reject the challenge
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get the server's certificate data (we only check the leaf certificate)
        // Note: For even more robust security, the entire certificate chain could be verified
        guard let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            logger?.error("No server certificate found")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Get the certificate data
        let serverCertificateData = SecCertificateCopyData(serverCertificate) as Data
        
        // Calculate the fingerprint
        let serverFingerprint = SHA256.hash(data: serverCertificateData).compactMap {
            String(format: "%02x", $0)
        }.joined()
        
        // Log the fingerprints for debugging
        logger?.debug("Expected fingerprint: \(expectedFingerprint)")
        logger?.debug("Server fingerprint: \(serverFingerprint)")
        
        // Verify that the fingerprints match
        if serverFingerprint == expectedFingerprint {
            logger?.info("Certificate fingerprint verified successfully")
            // If they match, accept the server's certificate
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            logger?.error("Certificate fingerprint mismatch: Expected \(expectedFingerprint), got \(serverFingerprint)")
            // If they don't match, reject the challenge
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

/// Factory for creating URLSessions with certificate pinning
public class SecureURLSessionFactory {
    
    /// Creates a URLSession with certificate pinning
    public static func createSession(expectedFingerprint: String, logger: PinningLogger? = nil) -> URLSession {
        let delegate = CertificatePinningDelegate(expectedFingerprint: expectedFingerprint, logger: logger)
        
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