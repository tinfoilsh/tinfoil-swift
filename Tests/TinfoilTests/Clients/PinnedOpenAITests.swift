import XCTest
import Foundation
@testable import Tinfoil

/// The OpenAI clients over pinned TLS: each request goes through the
/// connection's pinned transport, here a stand-in that records what it was
/// asked to send and to which key, and plays back a response.
final class PinnedOpenAITests: XCTestCase {
    private static let chat = #"{"id":"c","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi there"},"finish_reason":"stop"}]}"#

    private static func chunk(_ content: String) -> String {
        #"data: {"id":"c","object":"chat.completion.chunk","created":0,"model":"m","choices":[{"index":0,"delta":{"content":"\#(content)"}}]}"# + "\n\n"
    }

    private let query = ChatQuery(messages: [.user(.init(content: .string("hello")))], model: "m")

    /// Records each pinned send and answers it from a script.
    private final class PinnedTransport: @unchecked Sendable {
        private let lock = NSLock()
        private var _sent: [(request: URLRequest, fingerprint: String)] = []
        private let respond: @Sendable (Int) throws -> [String]

        /// respond receives how many sends came before and returns the body's
        /// chunks, or throws to fail the send.
        init(respond: @escaping @Sendable (Int) throws -> [String]) {
            self.respond = respond
        }

        var sent: [(request: URLRequest, fingerprint: String)] {
            lock.lock()
            defer { lock.unlock() }
            return _sent
        }

        func stream(_ request: URLRequest, _ fingerprint: String) async throws -> (AsyncThrowingStream<Data, Error>, HTTPURLResponse) {
            lock.lock()
            let attempt = _sent.count
            _sent.append((request, fingerprint))
            lock.unlock()
            let chunks = try respond(attempt)
            let body = AsyncThrowingStream<Data, Error> { continuation in
                chunks.forEach { continuation.yield(Data($0.utf8)) }
                continuation.finish()
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [
                "Content-Type": chunks.count > 1 ? "text/event-stream" : "application/json",
            ])!
            return (body, response)
        }
    }

    private func client(
        _ transport: PinnedTransport,
        network: FakeNetwork = FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) },
        userCacheSecret: String = ""
    ) async throws -> EnclaveOpenAIClient {
        let connection = try EnclaveConnection(
            handle: EnclaveHandle(
                enclave: "enclave.example",
                repo: "org/repo",
                attestationRelay: nil,
                attestor: Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0)
            ),
            transportMode: .tls,
            baseURL: nil,
            userCacheSecret: userCacheSecret,
            send: { _, _ in throw TinfoilError.configuration("the OpenAI client streams every request") },
            stream: { try await transport.stream($0, $1) }
        )
        return try EnclaveOpenAIClient(httpClient: await EnclaveHTTPClient(verifying: connection), apiKey: "test-key")
    }

    func testChatGoesOverThePinnedConnection() async throws {
        let transport = PinnedTransport { _ in [Self.chat] }
        let result = try await client(transport).chats(query: query)

        XCTAssertEqual(result.choices.first?.message.content, "hi there")
        let sent = try XCTUnwrap(transport.sent.first)
        XCTAssertEqual(sent.fingerprint, "deadbeef", "Pinned to the verified TLS key")
        XCTAssertEqual(sent.request.url?.host, "enclave.example")
        XCTAssertEqual(sent.request.url?.path, "/v1/chat/completions")
        XCTAssertEqual(sent.request.value(forHTTPHeaderField: "Authorization"), "Bearer test-key")
    }

    func testStreamedChatArrivesChunkByChunk() async throws {
        let transport = PinnedTransport { _ in [Self.chunk("Hel"), Self.chunk("lo"), "data: [DONE]\n\n"] }
        var content = ""
        var chunks = 0
        // The client is held for the whole stream, as a caller holds it.
        let client = try await client(transport)
        for try await result in client.chatsStream(query: query) {
            content += result.choices.first?.delta.content ?? ""
            chunks += 1
        }
        XCTAssertEqual(content, "Hello")
        XCTAssertEqual(chunks, 2)
        XCTAssertEqual(transport.sent.count, 1)
    }

    /// A stream keeps going after the caller releases the client that
    /// started it, as a URLSession-backed client's does.
    func testAStreamOutlivesItsClient() async throws {
        let transport = PinnedTransport { _ in [Self.chunk("Hel"), Self.chunk("lo"), "data: [DONE]\n\n"] }
        // The client exists only inside this closure.
        let stream = try await { [query] in try await self.client(transport).chatsStream(query: query) }()
        let content = try await withThrowingTaskGroup(of: String?.self) { group in
            group.addTask {
                var content = ""
                for try await result in stream {
                    content += result.choices.first?.delta.content ?? ""
                }
                return content
            }
            group.addTask {
                try await Task.sleep(nanoseconds: 10_000_000_000)
                return nil
            }
            let first = try await group.next() ?? nil
            group.cancelAll()
            return first
        }
        XCTAssertEqual(content, "Hello", "The stream must finish, not hang, once its client is released.")
    }

    /// A key that the enclave presents before anything was sent is verified
    /// again, and the request retried once against the new verification.
    func testARejectedKeyIsVerifiedAgainAndRetriedOnce() async throws {
        let network = FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) }
        let transport = PinnedTransport { attempt in
            if attempt == 0 {
                throw PinnedTLS.Rejection(host: "enclave.example", reason: "presented another key")
            }
            return [Self.chat]
        }
        let client = try await client(transport, network: network)
        let verifications = network.urls.count

        _ = try await client.chats(query: query)

        XCTAssertEqual(transport.sent.count, 2)
        XCTAssertEqual(network.urls.count, verifications + 1, "The rejection verified the enclave again.")
    }

    /// A rejection after a connection passed the pin may follow a request
    /// that reached the enclave, so it is not replayed.
    func testARejectionAfterTheRequestMayHaveLeftIsNotRetried() async throws {
        let transport = PinnedTransport { _ in
            throw PinnedTLS.Rejection(host: "enclave.example", reason: "presented another key", requestMayHaveBeenSent: true)
        }
        do {
            _ = try await client(transport).chats(query: query)
            XCTFail("expected the rejection")
        } catch TinfoilError.attestationError(let failure) {
            XCTAssertTrue(failure.message.contains("presented another key"), failure.message)
        }
        XCTAssertEqual(transport.sent.count, 1)
    }

    func testTheCacheSecretIsAddedToTheBody() async throws {
        let transport = PinnedTransport { _ in [Self.chat] }
        _ = try await client(transport, userCacheSecret: "scope-secret").chats(query: query)

        let body = try XCTUnwrap(transport.sent.first?.request.httpBody)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["user_cache_secret"] as? String, "scope-secret")
    }

    func testAnOpenAIClientOverAPinnedConnectionUsesItsMode() async throws {
        let client = try await client(PinnedTransport { _ in [Self.chat] })
        XCTAssertEqual(client.httpClient.transportMode, .tls)
    }
}
