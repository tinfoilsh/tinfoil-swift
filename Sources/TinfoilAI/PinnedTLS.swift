import Foundation
import CryptoKit
import Security

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The SHA-256 of a certificate's SubjectPublicKeyInfo, which is how an
/// attestation records the enclave's TLS key.
enum CertificateFingerprint {
    struct Malformed: Error {}

    private static let sequenceTag: UInt8 = 0x30
    private static let explicitVersionTag: UInt8 = 0xA0

    /// Hashes the subjectPublicKeyInfo field's DER exactly as it appears in the
    /// certificate, as Go's RawSubjectPublicKeyInfo does, so any key type works
    /// without re-encoding the key.
    static func spkiSHA256(certificateDER: Data) throws -> String {
        let bytes = ArraySlice(Array(certificateDER))
        guard let certificate = try elements(of: bytes).first, certificate.tag == sequenceTag,
              let tbs = try elements(of: certificate.contents).first, tbs.tag == sequenceTag
        else {
            throw Malformed()
        }
        // TBSCertificate: an optional explicit version, then serialNumber,
        // signature, issuer, validity, subject, subjectPublicKeyInfo.
        var fields = try elements(of: tbs.contents)[...]
        if fields.first?.tag == explicitVersionTag {
            fields = fields.dropFirst()
        }
        guard fields.count >= 6 else {
            throw Malformed()
        }
        let spki = fields[fields.startIndex + 5]
        guard spki.tag == sequenceTag else {
            throw Malformed()
        }
        return SHA256.hash(data: Data(spki.encoded)).map { String(format: "%02x", $0) }.joined()
    }

    private struct Element {
        let tag: UInt8
        let contents: ArraySlice<UInt8>
        let encoded: ArraySlice<UInt8>
    }

    /// Splits bytes into the DER elements they hold, in order.
    private static func elements(of bytes: ArraySlice<UInt8>) throws -> [Element] {
        var result: [Element] = []
        var index = bytes.startIndex
        while index < bytes.endIndex {
            let start = index
            let tag = bytes[index]
            index += 1
            guard index < bytes.endIndex else {
                throw Malformed()
            }
            var length = Int(bytes[index])
            index += 1
            if length & 0x80 != 0 {
                let count = length & 0x7F
                guard (1...4).contains(count), count <= bytes.endIndex - index else {
                    throw Malformed()
                }
                length = 0
                for _ in 0..<count {
                    length = length << 8 | Int(bytes[index])
                    index += 1
                }
            }
            guard length <= bytes.endIndex - index else {
                throw Malformed()
            }
            let end = index + length
            result.append(Element(tag: tag, contents: bytes[index..<end], encoded: bytes[start..<end]))
            index = end
        }
        return result
    }
}

/// Sends requests whose every TLS connection, redirects included, must present
/// the attested key: the system's usual certificate validation, then the
/// certificate's key fingerprint against the attestation's, as the Go SDK pins.
/// Each send has a session of its own, so no connection outlives the key it
/// was checked against.
enum PinnedTLS {
    typealias Send = @Sendable (_ request: URLRequest, _ fingerprint: String) async throws -> (Data, HTTPURLResponse)

    /// A TLS connection was refused because its certificate does not prove the
    /// attested key. Its handshake failed, so nothing went over it.
    struct Rejection: Error, CustomStringConvertible {
        let host: String
        let reason: String
        /// True when an earlier connection for the same request passed the pin,
        /// as when a redirect opens a new one: the request may already have
        /// reached the enclave, so it must not be replayed.
        let requestMayHaveBeenSent: Bool

        init(host: String, reason: String, requestMayHaveBeenSent: Bool = false) {
            self.host = host
            self.reason = reason
            self.requestMayHaveBeenSent = requestMayHaveBeenSent
        }

        var description: String { "\(host) \(reason)" }
    }

    /// - Parameter configuration: Tests substitute protocol classes.
    static func send(
        _ request: URLRequest,
        expecting fingerprint: String,
        configuration: URLSessionConfiguration = .ephemeral
    ) async throws -> (Data, HTTPURLResponse) {
        // "https:host/path" has a scheme but no host, yet URLSession would
        // still connect to host, so a host is required as well as HTTPS.
        guard let url = request.url, url.scheme?.lowercased() == "https", url.host != nil else {
            throw TinfoilError.invalidConfiguration("pinned requests need an HTTPS URL with a host, not \(request.url?.absoluteString ?? "no URL")")
        }
        let origin = URLHelpers.origin(from: url.absoluteString)
        guard !origin.isEmpty else {
            throw TinfoilError.invalidConfiguration("cannot pin a request to \(url.absoluteString)")
        }
        let pin = PinningDelegate(fingerprint: fingerprint, origin: origin)
        let session = URLSession(configuration: configuration, delegate: pin, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        do {
            let (data, response) = try await session.data(for: request)
            if let failure = pin.failure {
                throw failure
            }
            guard let response = response as? HTTPURLResponse else {
                throw URLError(.badServerResponse)
            }
            return (data, response)
        } catch {
            if let failure = pin.failure {
                throw failure
            }
            if Task.isCancelled {
                throw CancellationError()
            }
            throw error
        }
    }
}

final class PinningDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let fingerprint: String
    /// The origin every redirect must stay on
    private let origin: String
    private let lock = NSLock()
    private var _failure: Error?
    /// Connections that passed the pin, after which a request may have been sent
    private var pinnedConnections = 0

    init(fingerprint: String, origin: String) {
        self.fingerprint = fingerprint
        self.origin = origin
    }

    /// Why the session refused a connection or redirect, if it did
    var failure: Error? {
        lock.lock()
        defer { lock.unlock() }
        return _failure
    }

    private func fail(_ error: Error) {
        lock.lock()
        if _failure == nil {
            _failure = error
        }
        lock.unlock()
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
            // Only reachable over a connection that already passed the pin.
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let trust = challenge.protectionSpace.serverTrust
        if let trust, admit(trust, host: challenge.protectionSpace.host) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// Decides one server-trust challenge: the system's usual validation, then
    /// the certificate's key against the attested fingerprint. A challenge
    /// with no trust to evaluate is refused rather than left to the default.
    func admit(_ trust: SecTrust?, host: String) -> Bool {
        guard let trust else {
            reject(host, "offered no certificate to check")
            return false
        }
        guard SecTrustEvaluateWithError(trust, nil) else {
            reject(host, "presented a certificate that is not trusted")
            return false
        }
        guard let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first,
              let presented = try? CertificateFingerprint.spkiSHA256(certificateDER: SecCertificateCopyData(leaf) as Data),
              presented == fingerprint
        else {
            reject(host, "presented a certificate whose key does not match the attestation")
            return false
        }
        lock.lock()
        pinnedConnections += 1
        lock.unlock()
        return true
    }

    private func reject(_ host: String, _ reason: String) {
        lock.lock()
        let mayHaveSent = pinnedConnections > 0
        lock.unlock()
        fail(PinnedTLS.Rejection(host: host, reason: reason, requestMayHaveBeenSent: mayHaveSent))
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard let target = request.url, target.scheme?.lowercased() == "https" else {
            // A plain HTTP hop would carry the request's headers unpinned.
            fail(URLError(.appTransportSecurityRequiresSecureConnection, userInfo: [
                NSURLErrorFailingURLErrorKey: request.url as Any,
            ]))
            completionHandler(nil)
            return
        }
        // The pin would refuse another host's certificate before anything is
        // sent, but refusing here says why, rather than reporting a key
        // rejection that would only lead to verifying again.
        guard !origin.isEmpty, URLHelpers.origin(from: target.absoluteString) == origin else {
            fail(TinfoilError.connectionError("refusing redirect to \(target.absoluteString): requests stay on the verified enclave"))
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }
}
