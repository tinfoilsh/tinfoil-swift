import XCTest
import Foundation
@testable import TinfoilAI

/// Records each pinned send and answers from a script, in place of the network.
private final class SendLog: @unchecked Sendable {
    private let lock = NSLock()
    private var _sent: [(request: URLRequest, fingerprint: String)] = []
    private let respond: (Int) throws -> Void

    /// respond receives how many sends came before this one, and throws to
    /// fail it.
    init(respond: @escaping (Int) throws -> Void = { _ in }) {
        self.respond = respond
    }

    var sent: [(request: URLRequest, fingerprint: String)] {
        lock.lock()
        defer { lock.unlock() }
        return _sent
    }

    func send(_ request: URLRequest, _ fingerprint: String) throws -> (Data, HTTPURLResponse) {
        lock.lock()
        let previous = _sent.count
        _sent.append((request, fingerprint))
        lock.unlock()
        try respond(previous)
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        return (Data("ok".utf8), response)
    }
}

/// A clock tests move by hand
private final class Clock: @unchecked Sendable {
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

final class EnclaveHandleRequestTests: XCTestCase {
    private let rejection = PinnedTLS.Rejection(host: "enclave.example", reason: "presented a certificate whose key does not match the attestation")

    /// - Parameter evidenceClock: The clock new evidence's freshness counts
    ///   from; the handle's own clock by default.
    private func handle(
        network: FakeNetwork,
        log: SendLog,
        clock: Clock = Clock(),
        evidenceClock: (@Sendable () -> Date)? = nil
    ) throws -> EnclaveHandle {
        try EnclaveHandle(
            enclave: "enclave.example",
            repo: "org/repo",
            attestationRelay: nil,
            attestor: Attestor(
                verifier: FakeVerifier(now: evidenceClock ?? { clock.now }),
                fetch: { try network.fetch($0) },
                retryDelay: 0
            ),
            send: { try log.send($0, $1) },
            now: { clock.now }
        )
    }

    private func approving() -> FakeNetwork {
        FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) }
    }

    func testRelativeURLResolvesAgainstTheVerifiedEnclave() async throws {
        let log = SendLog()
        let handle = try handle(network: approving(), log: log)
        let before = await handle.enclaveURL
        XCTAssertNil(before)

        let (data, response) = try await handle.data(from: URL(string: "/health?verbose=1")!)

        XCTAssertEqual(data, Data("ok".utf8))
        XCTAssertEqual(response.statusCode, 200)
        let sent = try XCTUnwrap(log.sent.first)
        XCTAssertEqual(sent.request.url?.absoluteString, "https://enclave.example/health?verbose=1")
        XCTAssertEqual(sent.fingerprint, "deadbeef", "Pinned to the verification's TLS key")
        let after = await handle.enclaveURL
        XCTAssertEqual(after?.absoluteString, "https://enclave.example")
    }

    func testRequestKeepsMethodHeadersAndBody() async throws {
        let log = SendLog()
        let handle = try handle(network: approving(), log: log)
        var request = URLRequest(url: URL(string: "/v1/thing")!)
        request.httpMethod = "POST"
        request.setValue("Bearer key", forHTTPHeaderField: "Authorization")
        request.httpBody = Data("{}".utf8)

        _ = try await handle.data(for: request)

        let sent = try XCTUnwrap(log.sent.first).request
        XCTAssertEqual(sent.httpMethod, "POST")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "Authorization"), "Bearer key")
        XCTAssertEqual(sent.httpBody, Data("{}".utf8))
    }

    func testPlainHTTPIsRefused() async throws {
        let log = SendLog()
        let handle = try handle(network: approving(), log: log)

        do {
            _ = try await handle.data(from: URL(string: "http://enclave.example/health")!)
            XCTFail("a request with headers must not leave over plain HTTP")
        } catch TinfoilError.invalidConfiguration {
        }
        XCTAssertTrue(log.sent.isEmpty)
    }

    func testOtherHostsAreRefused() async throws {
        let network = approving()
        let log = SendLog()
        let handle = try handle(network: network, log: log)

        do {
            _ = try await handle.data(from: URL(string: "https://elsewhere.example/health")!)
            XCTFail("credentials must not be sent to another host")
        } catch TinfoilError.invalidConfiguration(let message) {
            XCTAssertTrue(message.contains("elsewhere.example"), message)
        }
        XCTAssertTrue(log.sent.isEmpty)
        XCTAssertEqual(network.urls.count, 1, "A refused host does not trigger verifying again.")
    }

    func testASchemeWithoutAHostIsRefused() async throws {
        // URLSession would connect to elsewhere.example for this URL, though
        // Foundation reports no host for it.
        let network = approving()
        let log = SendLog()
        let handle = try handle(network: network, log: log)

        do {
            _ = try await handle.data(from: URL(string: "https:elsewhere.example/collect")!)
            XCTFail("a URL naming another host without // must be refused")
        } catch TinfoilError.invalidConfiguration {
        }
        XCTAssertTrue(log.sent.isEmpty)
        XCTAssertEqual(network.urls.count, 1)

        do {
            _ = try await PinnedTLS.send(URLRequest(url: URL(string: "https:elsewhere.example/collect")!), expecting: "unused")
            XCTFail("the pinned send must refuse it as well")
        } catch TinfoilError.invalidConfiguration {
        }
    }

    func testTheEnclavesOwnAbsoluteURLIsAllowed() async throws {
        let log = SendLog()
        let handle = try handle(network: approving(), log: log)

        _ = try await handle.data(from: URL(string: "https://ENCLAVE.example:443/health")!)

        XCTAssertEqual(log.sent.count, 1)
    }

    private func stubbed() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return configuration
    }

    // The stub answers without TLS, so these exercise the redirect policy and
    // not the certificate pin, which the live tests cover.
    func testARedirectToAnotherHostIsRefused() async throws {
        let elsewhere = URL(string: "https://elsewhere.example/collect")!
        StubURLProtocol.serve { request in
            request.url == elsewhere ? .response(status: 200, body: Data()) : .redirect(to: elsewhere)
        }

        do {
            _ = try await PinnedTLS.send(
                URLRequest(url: URL(string: "https://enclave.example/health")!),
                expecting: "unused",
                configuration: stubbed()
            )
            XCTFail("a redirect off the enclave must be refused")
        } catch TinfoilError.connectionError(let message) {
            XCTAssertTrue(message.contains("elsewhere.example"), message)
        }
        XCTAssertFalse(StubURLProtocol.requests.contains { $0.url == elsewhere }, "The other host is never asked.")
    }

    func testARedirectWithinTheEnclaveIsFollowed() async throws {
        let moved = URL(string: "https://enclave.example/health/v2")!
        StubURLProtocol.serve { request in
            request.url == moved ? .response(status: 200, body: Data("ok".utf8)) : .redirect(to: moved)
        }

        let (data, response) = try await PinnedTLS.send(
            URLRequest(url: URL(string: "https://enclave.example/health")!),
            expecting: "unused",
            configuration: stubbed()
        )

        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(data, Data("ok".utf8))
    }

    func testARedirectToPlainHTTPIsRefused() async throws {
        let downgraded = URL(string: "http://enclave.example/health")!
        StubURLProtocol.serve { _ in .redirect(to: downgraded) }

        do {
            _ = try await PinnedTLS.send(
                URLRequest(url: URL(string: "https://enclave.example/health")!),
                expecting: "unused",
                configuration: stubbed()
            )
            XCTFail("a redirect to plain HTTP must be refused")
        } catch let error as URLError {
            XCTAssertEqual(error.code, .appTransportSecurityRequiresSecureConnection)
        }
        XCTAssertFalse(StubURLProtocol.requests.contains { $0.url == downgraded })
    }

    func testARejectedKeyIsVerifiedAgainAndRetriedOnce() async throws {
        let network = approving()
        let log = SendLog { previous in
            if previous == 0 { throw self.rejection }
        }
        let handle = try handle(network: network, log: log)

        _ = try await handle.data(from: URL(string: "/health")!)

        XCTAssertEqual(log.sent.count, 2)
        XCTAssertEqual(network.urls.count, 2, "The enclave was verified again before the retry.")
    }

    func testAKeyRejectedAfterVerifyingAgainFails() async throws {
        let network = approving()
        let log = SendLog { _ in throw self.rejection }
        let handle = try handle(network: network, log: log)

        do {
            _ = try await handle.data(from: URL(string: "/health")!)
            XCTFail("a key the attestation does not endorse must not be used")
        } catch TinfoilError.attestationError(let message) {
            XCTAssertTrue(message.contains("does not match the attestation"), message)
        }
        XCTAssertEqual(log.sent.count, 2)
        XCTAssertEqual(network.urls.count, 2)
    }

    func testARejectionAfterTheRequestMayHaveBeenSentIsNotRetried() async throws {
        let network = approving()
        let afterRedirect = PinnedTLS.Rejection(
            host: "enclave.example",
            reason: "presented a certificate whose key does not match the attestation",
            requestMayHaveBeenSent: true
        )
        let log = SendLog { _ in throw afterRedirect }
        let handle = try handle(network: network, log: log)

        do {
            _ = try await handle.data(for: URLRequest(url: URL(string: "/v1/thing")!))
            XCTFail("a request that may have reached the enclave must not be replayed")
        } catch TinfoilError.attestationError {
        }
        XCTAssertEqual(log.sent.count, 1)
        XCTAssertEqual(network.urls.count, 1, "Verifying again would only lead to a replay.")
    }

    func testAVerificationAlreadyPastItsDeadlineIsRefused() async throws {
        // The evidence is good for an hour of real time, but the handle's clock
        // is two hours ahead, so the new verification arrives already expired.
        let clock = Clock()
        clock.advance(by: 2 * 3600)
        let log = SendLog()
        let handle = try handle(network: approving(), log: log, clock: clock, evidenceClock: { Date() })

        do {
            _ = try await handle.data(from: URL(string: "/health")!)
            XCTFail("an expired verification must not authorize a request")
        } catch TinfoilError.attestationError(let message) {
            XCTAssertTrue(message.contains("freshness deadline"), message)
        }
        XCTAssertTrue(log.sent.isEmpty)
    }

    func testOtherErrorsAreNeitherRetriedNorWrapped() async throws {
        let network = approving()
        let log = SendLog { _ in throw URLError(.timedOut) }
        let handle = try handle(network: network, log: log)

        do {
            _ = try await handle.data(from: URL(string: "/health")!)
            XCTFail("the network error must surface")
        } catch let error as URLError {
            XCTAssertEqual(error.code, .timedOut)
        }
        XCTAssertEqual(log.sent.count, 1)
        XCTAssertEqual(network.urls.count, 1)
    }

    func testAnExpiredVerificationIsRenewedBeforeSending() async throws {
        let network = approving()
        let clock = Clock()
        let handle = try handle(network: network, log: SendLog(), clock: clock)

        _ = try await handle.data(from: URL(string: "/health")!)
        _ = try await handle.data(from: URL(string: "/health")!)
        XCTAssertEqual(network.urls.count, 1, "A current verification is reused.")

        clock.advance(by: 2 * 3600)
        _ = try await handle.data(from: URL(string: "/health")!)
        XCTAssertEqual(network.urls.count, 2, "An expired verification is renewed first.")
    }

    func testLivePinnedRequest() async throws {
        try requireLiveIntegration()
        let handle = try EnclaveHandle(enclave: TinfoilConstants.fallbackEnclave)

        let (data, response) = try await handle.data(from: URL(string: "/health")!)

        XCTAssertEqual(response.statusCode, 200)
        XCTAssertFalse(data.isEmpty)
    }

    func testLiveConnectionWithTheWrongKeyIsRefused() async throws {
        try requireLiveIntegration()
        let request = URLRequest(url: URL(string: "https://\(TinfoilConstants.fallbackEnclave)/health")!)

        do {
            _ = try await PinnedTLS.send(request, expecting: String(repeating: "0", count: 64))
            XCTFail("a certificate whose key is not the expected one must be refused")
        } catch let rejection as PinnedTLS.Rejection {
            XCTAssertEqual(rejection.host, TinfoilConstants.fallbackEnclave)
        }
    }
}
