import Foundation
@testable import Tinfoil

/// Stands in for the TinfoilGo verifier. A document is "<verdict>:<nonce hex>"; the
/// stand-in refuses one whose nonce is not the one it was given, so the tests
/// also prove the attestor carries a single nonce through each attempt.
final class FakeVerifier: AttestationVerifier, @unchecked Sendable {
    private let lock = NSLock()
    private var issued: UInt8 = 0
    private var _pins: [Pin] = []
    /// The clock a verification's hour of freshness is counted from
    private let now: @Sendable () -> Date
    /// A repo that checkPinVerifiability refuses
    private let refusedRepo: String?

    init(
        now: @escaping @Sendable () -> Date = { Date() },
        refusedRepo: String? = nil
    ) {
        self.now = now
        self.refusedRepo = refusedRepo
    }

    func checkPinVerifiability(_ pin: Pin) throws {
        if let refusedRepo, pin.repo == refusedRepo {
            throw TinfoilError.configuration("repo \(refusedRepo) cannot be verified")
        }
    }

    var pins: [Pin] {
        lock.lock()
        defer { lock.unlock() }
        return _pins
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

    func verify(document: Data, nonce: Data, pin: Pin) throws -> VerificationReport {
        lock.lock()
        _pins.append(pin)
        lock.unlock()
        let repo = pin.repo ?? pin.project ?? ""
        let parts = String(decoding: document, as: UTF8.self).split(separator: ":").map(String.init)
        guard parts.count == 2, parts[1] == nonce.hexString else {
            throw TinfoilError.attestation("document is not bound to the nonce")
        }
        switch parts[0] {
        case "ok":
            return .stub(repo: repo, expiresAt: now().addingTimeInterval(3600))
        case "tls-only":
            return .stub(repo: repo, expiresAt: now().addingTimeInterval(3600), hpkePublicKey: "")
        case "config":
            throw TinfoilError.configuration("bad repo")
        default:
            throw VerificationReport.rejection(layer: .policy, message: "policy: rejected")
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

extension VerificationReport {
    /// A 32-byte key, so a stub verification can configure EHBP.
    static let stubHPKEKey = String(repeating: "42", count: 32)

    /// The report of a verification against repo, which records the
    /// repository without its tag or digest pins, as the verifier does.
    static func stub(
        repo: String = TinfoilConstants.defaultGithubRepo,
        expiresAt: Date = Date().addingTimeInterval(3600),
        hpkePublicKey: String = stubHPKEKey
    ) -> VerificationReport {
        VerificationReport(
            steps: ["envelope", "provenance", "quote", "policy"].map {
                Step(layer: VerificationLayer(rawValue: $0), status: .passed, message: "")
            },
            verifiedFacts: .stub(repo: repo, expiresAt: expiresAt, hpkePublicKey: hpkePublicKey),
            partialFacts: nil,
            metadata: VerificationMetadata(
                verifier: SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion),
                verifiedAt: Date()
            )
        )
    }

    /// The error that the verifier's rejection at layer becomes: an
    /// attestation error whose verification error carries a report in which
    /// the step of layer failed, the earlier steps passed and the later ones
    /// did not run.
    static func rejection(layer: VerificationLayer, message: String) -> TinfoilError {
        let layers = ["envelope", "provenance", "quote", "policy"].map { VerificationLayer(rawValue: $0) }
        let failed = layers.firstIndex(of: layer) ?? layers.count
        let report = VerificationReport(
            steps: layers.enumerated().map { index, step in
                Step(
                    layer: step,
                    status: index < failed ? .passed : index == failed ? .failed : .notRun,
                    message: index == failed ? "verification error: \(message)" : ""
                )
            },
            verifiedFacts: nil,
            partialFacts: PartialFacts(
                expected: nil,
                measured: failed > 0 ? MeasuredFacts(cpu: nil, tlsPublicKeyFingerprint: "deadbeef", hpkePublicKeyFingerprint: "") : nil
            ),
            metadata: VerificationMetadata(
                verifier: SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion),
                verifiedAt: Date()
            )
        )
        return .attestation(message, layer: layer, verificationError: VerificationError(layer: layer, message: message, report: report))
    }
}

extension VerifiedFacts {
    /// Verified facts against repo, as `VerificationReport.stub` holds them
    static func stub(
        repo: String = TinfoilConstants.defaultGithubRepo,
        expiresAt: Date = Date().addingTimeInterval(3600),
        hpkePublicKey: String = VerificationReport.stubHPKEKey
    ) -> VerifiedFacts {
        VerifiedFacts(
            configRepo: String(repo.prefix { $0 != "@" }),
            codeDigest: "abc123",
            codeTag: "",
            codeMeasurement: nil,
            enclaveMeasurement: nil,
            config: nil,
            runtime: nil,
            platform: nil,
            tlsPublicKeyFingerprint: "deadbeef",
            hpkePublicKey: hpkePublicKey,
            cryptoMaterial: [
                .init(id: "tls", format: "https://tinfoil.sh/key/spki-fp-sha256/v1", data: "deadbeef"),
            ] + (hpkePublicKey.isEmpty ? [] : [.init(id: "hpke", format: "https://tinfoil.sh/key/x25519-hpke/v1", data: hpkePublicKey)]),
            freshnessExpiresAt: expiresAt
        )
    }
}

extension Result where Success == VerificationReport, Failure == TinfoilError {
    /// The report of an attempt that passed, or nil
    var report: VerificationReport? {
        try? get()
    }

    /// The error of an attempt that failed, or nil
    var error: TinfoilError? {
        guard case .failure(let error) = self else { return nil }
        return error
    }
}

extension TinfoilError {
    /// The verifier's error that this error carries, when the verifier
    /// rejected the document
    var verificationError: VerificationError? {
        guard case .attestationError(let failure) = self else { return nil }
        return failure.verificationError
    }
}

/// What an approval closure throws to reject a verification
struct Refusal: Error, CustomStringConvertible {
    var description: String { "refused by the test" }
}

extension TinfoilError {
    /// Whether this is the error an `verificationCheck` callback's `Refusal`
    /// becomes, rather than any other attestation failure
    var isRefusal: Bool {
        guard case .attestationError(let failure) = self, failure.layer == nil else { return false }
        return failure.message.contains("verification check rejected") && failure.message.contains(Refusal().description)
    }
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

/// A value that a test changes while the code under test reads it, as a
/// verdict that a fake network serves
final class Verdict: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: String

    init(_ value: String) {
        _value = value
    }

    var value: String {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}

/// A clock tests move by hand
final class ManualClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current = Date()

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    func advance(by seconds: TimeInterval) {
        lock.lock()
        current += seconds
        lock.unlock()
    }
}

/// Serves canned responses to sessions configured with it, so fetches to
/// https URLs run without a network or TLS.
final class StubURLProtocol: URLProtocol {
    enum Reply {
        case response(status: Int, body: Data)
        case redirect(to: URL)
        /// Answers with a 200 and body only after delay seconds.
        case delayed(TimeInterval, body: Data)
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
        let reply = Self.reply
        Self.lock.unlock()

        let url = request.url!
        switch reply(request) {
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
        case .delayed(let delay, let body):
            DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
                Self.lock.lock()
                let stopped = self.isStopped
                Self.lock.unlock()
                guard !stopped else { return }
                let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
                self.client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                self.client?.urlProtocol(self, didLoad: body)
                self.client?.urlProtocolDidFinishLoading(self)
            }
        case .hang:
            break
        case .failure(let error):
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    /// Set once the session stops loading, as on a timeout, after which a
    /// delayed reply is dropped.
    nonisolated(unsafe) private var isStopped = false

    override func stopLoading() {
        Self.lock.lock()
        isStopped = true
        Self.lock.unlock()
    }
}
