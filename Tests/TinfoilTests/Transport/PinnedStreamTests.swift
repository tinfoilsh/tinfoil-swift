import XCTest
import Foundation
@testable import Tinfoil

/// `PinnedTLS.stream` over a stub protocol: the headers arrive first, then
/// the body as the server sends it. The stub has no TLS, so the pin itself is
/// covered by the PinningDelegate tests.
final class PinnedStreamTests: XCTestCase {
    /// Answers each request from `respond`: a response and body chunks, or an
    /// error before any response.
    private final class StubProtocol: URLProtocol {
        nonisolated(unsafe) static var respond: ((URLRequest) -> Result<(HTTPURLResponse, [Data]), Error>)?

        override class func canInit(with request: URLRequest) -> Bool { true }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

        override func startLoading() {
            switch Self.respond?(request) ?? .failure(URLError(.unknown)) {
            case let .success((response, chunks)):
                client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
                for chunk in chunks {
                    client?.urlProtocol(self, didLoad: chunk)
                }
                client?.urlProtocolDidFinishLoading(self)
            case let .failure(error):
                client?.urlProtocol(self, didFailWithError: error)
            }
        }

        override func stopLoading() {}
    }

    private var configuration: URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubProtocol.self]
        return configuration
    }

    private let request = URLRequest(url: URL(string: "https://enclave.example/v1/chat/completions")!)

    override func tearDown() {
        StubProtocol.respond = nil
        super.tearDown()
    }

    func testDeliversTheHeadersThenTheBody() async throws {
        StubProtocol.respond = { request in
            .success((
                HTTPURLResponse(url: request.url!, statusCode: 201, httpVersion: nil, headerFields: ["X-Test": "yes"])!,
                [Data("first ".utf8), Data("second".utf8)]
            ))
        }
        let (body, response) = try await PinnedTLS.stream(request, expecting: "deadbeef", configuration: configuration)
        XCTAssertEqual(response.statusCode, 201)
        XCTAssertEqual(response.value(forHTTPHeaderField: "X-Test"), "yes")
        var received = Data()
        for try await chunk in body {
            received.append(chunk)
        }
        XCTAssertEqual(String(decoding: received, as: UTF8.self), "first second")
    }

    func testAFailureBeforeTheHeadersIsThrown() async throws {
        StubProtocol.respond = { _ in .failure(URLError(.timedOut)) }
        do {
            _ = try await PinnedTLS.stream(request, expecting: "deadbeef", configuration: configuration)
            XCTFail("expected the failure")
        } catch let error as URLError {
            XCTAssertEqual(error.code, .timedOut)
        }
    }

    func testRefusesAURLThatIsNotHTTPSWithAHost() async {
        for target in ["http://enclave.example/x", "https:enclave.example/x"] {
            do {
                _ = try await PinnedTLS.stream(URLRequest(url: URL(string: target)!), expecting: "deadbeef", configuration: configuration)
                XCTFail("\(target) must be refused")
            } catch TinfoilError.configurationError {
            } catch {
                XCTFail("unexpected error \(error)")
            }
        }
    }
}

/// Cancelling a caller of `StreamingSession.data(for:delegate:)` cancels the
/// request it started, as URLSession's own method does.
final class StreamingSessionCancellationTests: XCTestCase {
    func testCancellingTheCallerCancelsTheRequest() async throws {
        let opened = AsyncGate()
        let sawCancellation = Box(value: false)
        let session = StreamingSession(delegate: nil) { _ in
            await opened.open()
            do {
                try await Task.sleep(nanoseconds: 10_000_000_000)
            } catch {
                sawCancellation.value = true
                throw error
            }
            throw TinfoilError.network("not reached")
        }
        let caller = Task {
            try await session.data(for: URLRequest(url: URL(string: "https://enclave.example/v1/x")!), delegate: nil)
        }
        await opened.wait()
        caller.cancel()
        do {
            _ = try await caller.value
            XCTFail("a cancelled request must not complete")
        } catch {
        }
        XCTAssertTrue(sawCancellation.value, "The request saw the caller's cancellation.")
    }
}

/// A completed request through `StreamingSession.data(for:delegate:)` is
/// released, not kept alive by its cancellation handling.
final class StreamingSessionReleaseTests: XCTestCase {
    private final class Sentinel: Sendable {}

    func testATaskThatNeverStartsDoesNotKeepItsSessionAlive() {
        weak var released: Sentinel?
        do {
            let sentinel = Sentinel()
            released = sentinel
            let session = StreamingSession(delegate: nil) { _ in
                _ = sentinel
                throw TinfoilError.network("not reached")
            }
            _ = session.dataTask(with: URLRequest(url: URL(string: "https://enclave.example/v1/x")!))
        }
        XCTAssertNil(released, "An unstarted task and its session are released together.")
    }

    func testACompletedTaskIsReleased() async throws {
        weak var released: Sentinel?
        do {
            // The open function, which a finished task holds, captures it.
            let sentinel = Sentinel()
            released = sentinel
            let session = StreamingSession(delegate: nil) { request in
                _ = sentinel
                let body = AsyncThrowingStream<Data, Error> { $0.yield(Data("ok".utf8)); $0.finish() }
                return (body, HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
            }
            let (data, _) = try await session.data(for: URLRequest(url: URL(string: "https://enclave.example/v1/x")!), delegate: nil)
            XCTAssertEqual(data, Data("ok".utf8))
        }
        for _ in 0..<100 where released != nil {
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTAssertNil(released, "Nothing keeps a finished task, or the open function it holds, alive.")
    }
}

#if canImport(Combine)
import Combine

/// Cancelling a subscription to `StreamingSession.dataTaskPublisher(for:)`
/// cancels its request, as URLSession's own publisher does.
final class StreamingSessionPublisherTests: XCTestCase {
    func testCancellingTheSubscriptionCancelsTheRequest() async throws {
        let opened = AsyncGate()
        let cancelled = expectation(description: "the request sees the cancellation")
        let session = StreamingSession(delegate: nil) { _ in
            await opened.open()
            do {
                try await Task.sleep(nanoseconds: 10_000_000_000)
            } catch {
                cancelled.fulfill()
                throw error
            }
            throw TinfoilError.network("not reached")
        }
        let subscription = session.dataTaskPublisher(for: URLRequest(url: URL(string: "https://enclave.example/v1/x")!))
            .sink(receiveCompletion: { _ in }, receiveValue: { _ in })
        await opened.wait()
        subscription.cancel()
        // Bounded, so a regression fails rather than hangs the suite.
        await fulfillment(of: [cancelled], timeout: 5)
    }
}
#endif
