import XCTest
import Foundation
@testable import Tinfoil

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

/// Requests through an enclave connection in TLS mode, as EnclaveHTTPClient
/// and RouterHTTPClient send them, with pinned sends recorded in place of the
/// network. The connection verifies lazily, so these tests also see when it
/// verifies.
final class EnclaveHTTPClientRequestTests: XCTestCase {
    private let rejection = PinnedTLS.Rejection(host: "enclave.example", reason: "presented a certificate whose key does not match the attestation")

    /// - Parameters:
    ///   - evidenceClock: The clock new evidence's freshness counts from; the
    ///     client's own clock by default.
    ///   - fetch: Fetches attestation documents; network's by default.
    private func client(
        network: FakeNetwork,
        log: SendLog,
        fetch: Attestor.Fetch? = nil,
        clock: ManualClock = ManualClock(),
        evidenceClock: (@Sendable () -> Date)? = nil,
        baseURL: URL? = nil,
        userCacheSecret: String = ""
    ) throws -> EnclaveConnection {
        try EnclaveConnection(
            handle: EnclaveHandle(
                enclave: "enclave.example",
                repo: "org/repo",
                attestationRelay: nil,
                attestor: Attestor(
                    verifier: FakeVerifier(now: evidenceClock ?? { clock.now }),
                    fetch: fetch ?? { try network.fetch($0) },
                    retryDelay: 0
                ),
                now: { clock.now }
            ),
            transportMode: .tls,
            baseURL: baseURL,
            userCacheSecret: userCacheSecret,
            send: { try log.send($0, $1) }
        )
    }

    private func approving() -> FakeNetwork {
        FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) }
    }

    func testRelativeURLResolvesAgainstTheBaseURL() async throws {
        let log = SendLog()
        let client = try client(network: approving(), log: log)
        XCTAssertEqual(client.baseURL.absoluteString, "https://enclave.example/")
        let before = await client.current
        XCTAssertNil(before, "Creating a connection does no network I/O.")

        let (data, response) = try await client.data(from: URL(string: "/health?verbose=1")!)

        XCTAssertEqual(data, Data("ok".utf8))
        XCTAssertEqual(response.statusCode, 200)
        let sent = try XCTUnwrap(log.sent.first)
        XCTAssertEqual(sent.request.url?.absoluteString, "https://enclave.example/health?verbose=1")
        XCTAssertEqual(sent.fingerprint, "deadbeef", "Pinned to the verification's TLS key")
        let after = await client.current
        XCTAssertEqual(after?.enclaveHost, "enclave.example")
    }

    func testRelativeURLResolvesAgainstABaseURLPath() async throws {
        let log = SendLog()
        let client = try client(network: approving(), log: log, baseURL: URL(string: "https://enclave.example/api/")!)

        _ = try await client.data(from: URL(string: "v1/models")!)

        XCTAssertEqual(log.sent.first?.request.url?.absoluteString, "https://enclave.example/api/v1/models")
    }

    func testTheCacheSecretIsInjectedOverPinnedTLS() async throws {
        let log = SendLog()
        let client = try client(network: approving(), log: log, userCacheSecret: "client-level")
        var request = URLRequest(url: URL(string: "/v1/chat/completions")!)
        request.httpMethod = "POST"
        request.httpBody = Data(#"{"model":"m"}"#.utf8)

        _ = try await client.data(for: request)

        let body = try XCTUnwrap(log.sent.first?.request.httpBody)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["user_cache_secret"] as? String, "client-level")
    }

    func testRequestKeepsMethodHeadersAndBody() async throws {
        let log = SendLog()
        let client = try client(network: approving(), log: log)
        var request = URLRequest(url: URL(string: "/v1/thing")!)
        request.httpMethod = "POST"
        request.setValue("Bearer key", forHTTPHeaderField: "Authorization")
        request.httpBody = Data("{}".utf8)

        _ = try await client.data(for: request)

        let sent = try XCTUnwrap(log.sent.first).request
        XCTAssertEqual(sent.httpMethod, "POST")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "Authorization"), "Bearer key")
        XCTAssertEqual(sent.httpBody, Data("{}".utf8))
    }

    func testPlainHTTPIsRefused() async throws {
        let log = SendLog()
        let client = try client(network: approving(), log: log)

        do {
            _ = try await client.data(from: URL(string: "http://enclave.example/health")!)
            XCTFail("a request with headers must not leave over plain HTTP")
        } catch TinfoilError.configurationError {
        }
        XCTAssertTrue(log.sent.isEmpty)
    }

    func testOtherHostsAreRefused() async throws {
        let network = approving()
        let log = SendLog()
        let client = try client(network: network, log: log)

        do {
            _ = try await client.data(from: URL(string: "https://elsewhere.example/health")!)
            XCTFail("credentials must not be sent to another host")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains("elsewhere.example"), failure.message)
        }
        XCTAssertTrue(log.sent.isEmpty)
        XCTAssertTrue(network.urls.isEmpty, "A refused request is refused before verifying.")
    }

    func testCredentialsInARequestURLAreRefused() async throws {
        let network = approving()
        let log = SendLog()
        let client = try client(network: network, log: log)

        do {
            _ = try await client.data(from: URL(string: "https://user:secret@enclave.example/health")!)
            XCTFail("credentials in a request URL must not reach the enclave")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertFalse(failure.message.contains("secret"), "The credentials aren't echoed: \(failure.message)")
        }
        XCTAssertTrue(log.sent.isEmpty)
        XCTAssertTrue(network.urls.isEmpty, "A refused request is refused before verifying.")
    }

    func testASchemeWithoutAHostIsRefused() async throws {
        // URLSession would connect to elsewhere.example for this URL, though
        // Foundation reports no host for it.
        let network = approving()
        let log = SendLog()
        let client = try client(network: network, log: log)

        do {
            _ = try await client.data(from: URL(string: "https:elsewhere.example/collect")!)
            XCTFail("a URL naming another host without // must be refused")
        } catch TinfoilError.configurationError {
        }
        XCTAssertTrue(log.sent.isEmpty)
        XCTAssertTrue(network.urls.isEmpty, "A refused request is refused before verifying.")

        StubURLProtocol.serve { _ in .response(status: 200, body: Data()) }
        do {
            _ = try await PinnedTLS.send(
                URLRequest(url: URL(string: "https:elsewhere.example/collect")!),
                expecting: "unused",
                configuration: stubbed()
            )
            XCTFail("the pinned send must refuse it as well")
        } catch TinfoilError.configurationError {
        }
        XCTAssertTrue(StubURLProtocol.requests.isEmpty)
    }

    func testTheEnclavesOwnAbsoluteURLIsAllowed() async throws {
        let log = SendLog()
        let client = try client(network: approving(), log: log)

        _ = try await client.data(from: URL(string: "https://ENCLAVE.example:443/health")!)

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
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains("elsewhere.example"), failure.message)
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
        let client = try client(network: network, log: log)

        _ = try await client.data(from: URL(string: "/health")!)

        XCTAssertEqual(log.sent.count, 2)
        XCTAssertEqual(network.urls.count, 2, "The enclave was verified again before the retry.")
    }

    func testCancellingDuringTheNewVerificationPreventsTheRetry() async throws {
        let network = approving()
        let log = SendLog { previous in
            if previous == 0 { throw self.rejection }
        }
        let gate = AsyncGate()
        let verifyingAgain = expectation(description: "verifying again after the rejection")
        let client = try client(network: network, log: log, fetch: { url in
            if network.urls.count == 1 {
                verifyingAgain.fulfill()
                await gate.wait()
            }
            return try network.fetch(url)
        })

        let request = Task { try await client.data(from: URL(string: "/health")!) }
        await fulfillment(of: [verifyingAgain], timeout: 1)
        // As when the user signs out while the request waits to be retried
        request.cancel()
        await gate.open()

        do {
            _ = try await request.value
            XCTFail("a cancelled request must not be retried")
        } catch is CancellationError {
        }
        XCTAssertEqual(log.sent.count, 1, "The request was not sent again.")
    }

    func testAKeyRejectedAfterVerifyingAgainFails() async throws {
        let network = approving()
        let log = SendLog { _ in throw self.rejection }
        let client = try client(network: network, log: log)

        do {
            _ = try await client.data(from: URL(string: "/health")!)
            XCTFail("a key the attestation does not endorse must not be used")
        } catch TinfoilError.attestationError(let failure) {
            XCTAssertTrue(failure.message.contains("does not match the attestation"), failure.message)
        }
        XCTAssertEqual(log.sent.count, 2)
        XCTAssertEqual(network.urls.count, 2)
    }

    func testARejectionAfterTheRequestMayHaveBeenSentIsNotRetried() async throws {
        let network = approving()
        let afterRedirect = PinnedTLS.Rejection(
            host: rejection.host,
            reason: rejection.reason,
            requestMayHaveBeenSent: true
        )
        let log = SendLog { _ in throw afterRedirect }
        let client = try client(network: network, log: log)

        do {
            _ = try await client.data(for: URLRequest(url: URL(string: "/v1/thing")!))
            XCTFail("a request that may have reached the enclave must not be replayed")
        } catch TinfoilError.attestationError {
        }
        XCTAssertEqual(log.sent.count, 1)
        XCTAssertEqual(network.urls.count, 1, "Verifying again would only lead to a replay.")
    }

    func testAVerificationAlreadyPastItsDeadlineIsRefused() async throws {
        // The evidence is good for an hour of real time, but the client's clock
        // is two hours ahead, so the new verification arrives already expired.
        let clock = ManualClock()
        clock.advance(by: 2 * 3600)
        let log = SendLog()
        let client = try client(network: approving(), log: log, clock: clock, evidenceClock: { Date() })

        do {
            _ = try await client.data(from: URL(string: "/health")!)
            XCTFail("an expired verification must not authorize a request")
        } catch TinfoilError.attestationError(let failure) {
            XCTAssertTrue(failure.message.contains("freshness deadline"), failure.message)
        }
        XCTAssertTrue(log.sent.isEmpty)
    }

    func testOtherErrorsAreNeitherRetriedNorWrapped() async throws {
        let network = approving()
        let log = SendLog { _ in throw URLError(.timedOut) }
        let client = try client(network: network, log: log)

        do {
            _ = try await client.data(from: URL(string: "/health")!)
            XCTFail("the network error must surface")
        } catch let error as URLError {
            XCTAssertEqual(error.code, .timedOut)
        }
        XCTAssertEqual(log.sent.count, 1)
        XCTAssertEqual(network.urls.count, 1)
    }

    func testAnExpiredVerificationIsRenewedBeforeSending() async throws {
        let network = approving()
        let clock = ManualClock()
        let client = try client(network: network, log: SendLog(), clock: clock)

        _ = try await client.data(from: URL(string: "/health")!)
        _ = try await client.data(from: URL(string: "/health")!)
        XCTAssertEqual(network.urls.count, 1, "A current verification is reused.")

        clock.advance(by: 2 * 3600)
        _ = try await client.data(from: URL(string: "/health")!)
        XCTAssertEqual(network.urls.count, 2, "An expired verification is renewed first.")
    }

    func testLivePinnedRequest() async throws {
        try requireLiveIntegration()
        let client = try await EnclaveHTTPClient(enclave: TinfoilConstants.fallbackEnclave, repo: TinfoilConstants.defaultGithubRepo)

        let (data, response) = try await client.data(from: URL(string: "/health")!)

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
