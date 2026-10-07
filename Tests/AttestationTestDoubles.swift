import Foundation
@testable import TinfoilAI

/// Stands in for the Go verifier. A document is "<verdict>:<nonce hex>"; the
/// stand-in refuses one whose nonce is not the one it was given, so the tests
/// also prove the attestor carries a single nonce through each attempt.
final class FakeVerifier: AttestationVerifier, @unchecked Sendable {
    private let lock = NSLock()
    private var issued: UInt8 = 0
    private var _repos: [String] = []
    /// The clock a verification's hour of freshness is counted from
    private let now: @Sendable () -> Date

    init(now: @escaping @Sendable () -> Date = { Date() }) {
        self.now = now
    }

    var repos: [String] {
        lock.lock()
        defer { lock.unlock() }
        return _repos
    }

    func newNonce() -> Data {
        lock.lock()
        defer { lock.unlock() }
        issued += 1
        return Data(repeating: issued, count: 32)
    }

    func attestationURL(host: String, relay: String?, nonce: Data) throws -> URL {
        var url = "https://\(relay ?? host)/.well-known/tinfoil-attestation?nonce=\(nonce.hexString)"
        if relay != nil {
            url += "&enclave=\(host)"
        }
        return URL(string: url)!
    }

    func verify(document: Data, nonce: Data, repo: String, enclaveHost: String) throws -> Verification {
        lock.lock()
        _repos.append(repo)
        lock.unlock()
        let parts = String(decoding: document, as: UTF8.self).split(separator: ":").map(String.init)
        guard parts.count == 2, parts[1] == nonce.hexString else {
            throw TinfoilError.attestationError("document is not bound to the nonce")
        }
        switch parts[0] {
        case "ok":
            return .stub(host: enclaveHost, repo: repo, expiresAt: now().addingTimeInterval(3600))
        case "config":
            throw TinfoilError.invalidConfiguration("bad repo")
        default:
            throw TinfoilError.attestationError("rejected")
        }
    }
}

/// Serves each fetch from a script and records the URLs asked for.
final class FakeNetwork: @unchecked Sendable {
    private let lock = NSLock()
    private var _urls: [URL] = []
    private let respond: (URL, Int) throws -> String

    /// respond receives the URL and how many times its host has been fetched
    /// before.
    init(respond: @escaping (URL, Int) throws -> String) {
        self.respond = respond
    }

    var urls: [URL] {
        lock.lock()
        defer { lock.unlock() }
        return _urls
    }

    func fetch(_ url: URL) throws -> Data {
        lock.lock()
        let previous = _urls.filter { $0.host == url.host }.count
        _urls.append(url)
        lock.unlock()
        return Data(try respond(url, previous).utf8)
    }

    /// A document with the given verdict, bound to the nonce in url.
    static func document(_ verdict: String, for url: URL) -> String {
        let nonce = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?.first { $0.name == "nonce" }?.value ?? ""
        return "\(verdict):\(nonce)"
    }
}

extension Verification {
    /// A 32-byte key, so a stub verification can configure EHBP.
    static let stubHPKEKey = String(repeating: "42", count: 32)

    /// A verification of host against repo, which records the repository
    /// without its tag or digest pins, as the verifier does.
    static func stub(
        host: String,
        repo: String = TinfoilConstants.defaultGithubRepo,
        expiresAt: Date = Date().addingTimeInterval(3600)
    ) -> Verification {
        Verification(
            enclaveHost: host,
            configRepo: String(repo.prefix { $0 != "@" }),
            codeDigest: "abc123",
            codeTag: nil,
            codeMeasurement: nil,
            enclaveMeasurement: nil,
            tlsPublicKeyFingerprint: "deadbeef",
            hpkePublicKey: stubHPKEKey,
            cryptoMaterial: [
                .init(id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: "deadbeef"),
                .init(id: "hpke", format: "https://tinfoil.sh/key/x25519-hpke/v1", data: stubHPKEKey),
            ],
            freshnessExpiresAt: expiresAt,
            verifiedAt: Date(),
            verifier: SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion)
        )
    }
}

/// What an approval closure throws to reject a verification
struct Refusal: Error, CustomStringConvertible {
    var description: String { "refused by the test" }
}

/// Records values from Sendable closures, in order.
final class Recorder<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var _values: [Value] = []

    var values: [Value] {
        lock.lock()
        defer { lock.unlock() }
        return _values
    }

    /// Appends value and returns how many have been recorded.
    @discardableResult
    func record(_ value: Value) -> Int {
        lock.lock()
        defer { lock.unlock() }
        _values.append(value)
        return _values.count
    }
}

/// Serves canned responses to sessions configured with it, so fetches to
/// https URLs run without a network or TLS.
final class StubURLProtocol: URLProtocol {
    enum Reply {
        case response(status: Int, body: Data)
        case redirect(to: URL)
        /// Never answers, so the request ends only by timeout or cancellation.
        case hang
        /// Fails in transit, as when offline.
        case failure(URLError)
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var reply: (URLRequest) -> Reply = { _ in .response(status: 200, body: Data()) }
    nonisolated(unsafe) private static var recorded: [URLRequest] = []

    static func serve(_ reply: @escaping (URLRequest) -> Reply) {
        lock.lock()
        defer { lock.unlock() }
        self.reply = reply
        recorded = []
    }

    static var requests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        Self.recorded.append(request)
        let reply = Self.reply(request)
        Self.lock.unlock()

        let url = request.url!
        switch reply {
        case .response(let status, let body):
            let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        case .redirect(let location):
            let response = HTTPURLResponse(
                url: url, statusCode: 302, httpVersion: "HTTP/1.1",
                headerFields: ["Location": location.absoluteString]
            )!
            var next = URLRequest(url: location)
            next.allHTTPHeaderFields = request.allHTTPHeaderFields
            client?.urlProtocol(self, wasRedirectedTo: next, redirectResponse: response)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)
        case .hang:
            break
        case .failure(let error):
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
