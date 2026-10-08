import XCTest
import Foundation
@testable import TinfoilAI

/// Serves canned responses to sessions configured with it, so fetches to
/// https URLs run without a network or TLS.
private final class StubURLProtocol: URLProtocol {
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

final class AttestationFetcherTests: XCTestCase {
    private let documentURL = URL(string: "https://enclave.example/.well-known/tinfoil-attestation?nonce=00")!

    private func fetcher(timeout: TimeInterval = 30, maximumBodyBytes: Int = 32 << 20) -> AttestationFetcher {
        AttestationFetcher(timeout: timeout, maximumBodyBytes: maximumBodyBytes) {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.protocolClasses = [StubURLProtocol.self]
            return configuration
        }
    }

    /// - Parameters:
    ///   - urlError: The code of the network error it must carry, if any.
    ///   - status: The HTTP status it must carry, if any.
    private func assertFetchError(
        _ body: () async throws -> Data,
        containing expected: String,
        urlError expectedCode: URLError.Code? = nil,
        status expectedStatus: Int? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await body()
            XCTFail("expected a fetch error mentioning \(expected)", file: file, line: line)
        } catch TinfoilError.fetchError(let message, let urlError, let status) {
            XCTAssertTrue(message.contains(expected), "\(message) should mention \(expected)", file: file, line: line)
            XCTAssertEqual(urlError?.code, expectedCode, file: file, line: line)
            XCTAssertEqual(status, expectedStatus, file: file, line: line)
        } catch {
            XCTFail("expected a fetch error, got \(error)", file: file, line: line)
        }
    }

    func testReturnsBodyAndIdentifiesTheSDK() async throws {
        StubURLProtocol.serve { _ in .response(status: 200, body: Data("document".utf8)) }

        let body = try await fetcher().fetch(documentURL)

        XCTAssertEqual(body, Data("document".utf8))
        let request = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Tinfoil-SDK"), TinfoilConstants.sdkName)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Tinfoil-SDK-Version"), TinfoilConstants.sdkVersion)
    }

    func testRefusesPlainHTTPBeforeSending() async {
        StubURLProtocol.serve { _ in .response(status: 200, body: Data()) }

        do {
            _ = try await fetcher().fetch(URL(string: "http://enclave.example/.well-known/tinfoil-attestation")!)
            XCTFail("a plain HTTP URL must be refused")
        } catch TinfoilError.invalidConfiguration {
        } catch {
            XCTFail("expected a configuration error, got \(error)")
        }
        XCTAssertTrue(StubURLProtocol.requests.isEmpty)
    }

    func testFollowsHTTPSRedirect() async throws {
        let moved = URL(string: "https://replica.example/.well-known/tinfoil-attestation?nonce=00")!
        StubURLProtocol.serve { request in
            request.url == moved ? .response(status: 200, body: Data("document".utf8)) : .redirect(to: moved)
        }

        let body = try await fetcher().fetch(documentURL)

        XCTAssertEqual(body, Data("document".utf8))
        XCTAssertEqual(StubURLProtocol.requests.map(\.url), [documentURL, moved])
    }

    func testRefusesRedirectToPlainHTTP() async {
        let downgraded = URL(string: "http://enclave.example/.well-known/tinfoil-attestation?nonce=00")!
        StubURLProtocol.serve { _ in .redirect(to: downgraded) }

        await assertFetchError({ try await self.fetcher().fetch(self.documentURL) }, containing: "non-HTTPS")
        XCTAssertFalse(StubURLProtocol.requests.contains { $0.url == downgraded }, "The plain HTTP URL must not be requested.")
    }

    func testStopsAfterTooManyRedirects() async {
        StubURLProtocol.serve { request in
            let hop = Int(request.url?.lastPathComponent ?? "") ?? 0
            return .redirect(to: URL(string: "https://enclave.example/\(hop + 1)")!)
        }

        await assertFetchError(
            { try await self.fetcher().fetch(self.documentURL) },
            containing: "stopped after \(AttestationFetcher.maximumRedirects) redirects"
        )
        XCTAssertEqual(StubURLProtocol.requests.count, AttestationFetcher.maximumRedirects + 1)
    }

    func testRejectsUnsuccessfulStatus() async {
        StubURLProtocol.serve { _ in .response(status: 503, body: Data("unavailable".utf8)) }

        await assertFetchError({ try await self.fetcher().fetch(self.documentURL) }, containing: "503", status: 503)
    }

    func testKeepsTheNetworkError() async {
        StubURLProtocol.serve { _ in .failure(URLError(.notConnectedToInternet)) }

        await assertFetchError(
            { try await self.fetcher().fetch(self.documentURL) },
            containing: self.documentURL.absoluteString,
            urlError: .notConnectedToInternet
        )
    }

    func testCapsTheBody() async throws {
        StubURLProtocol.serve { _ in .response(status: 200, body: Data(repeating: 0x61, count: 16)) }
        let atCap = try await fetcher(maximumBodyBytes: 16).fetch(documentURL)
        XCTAssertEqual(atCap.count, 16)

        await assertFetchError({ try await self.fetcher(maximumBodyBytes: 15).fetch(self.documentURL) }, containing: "exceeds 15 bytes")
    }

    func testTimesOut() async {
        StubURLProtocol.serve { _ in .hang }

        await assertFetchError({ try await self.fetcher(timeout: 0.5).fetch(self.documentURL) }, containing: "timed out", urlError: .timedOut)
    }

    func testCancellationStopsTheFetch() async {
        StubURLProtocol.serve { _ in .hang }
        let fetch = Task { try await self.fetcher().fetch(self.documentURL) }
        try? await Task.sleep(nanoseconds: 100_000_000)
        fetch.cancel()

        do {
            _ = try await fetch.value
            XCTFail("a cancelled fetch must not succeed")
        } catch is CancellationError {
        } catch {
            XCTFail("expected CancellationError, got \(error)")
        }
    }
}
