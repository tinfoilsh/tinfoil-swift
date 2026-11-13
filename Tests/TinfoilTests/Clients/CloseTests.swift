import XCTest
import Foundation
@testable import Tinfoil

/// A closed client refuses every later request and verification, from the
/// HTTP client and from an OpenAI client over it, without network I/O.
final class CloseTests: XCTestCase {
    private let query = ChatQuery(messages: [.user(.init(content: .string("hello")))], model: "m")

    private func connection(
        _ network: FakeNetwork,
        transportMode: TransportMode,
        send: @escaping PinnedTLS.Send = { _, _ in throw TinfoilError.network("no network in this test") },
        stream: @escaping PinnedTLS.Stream = { _, _ in throw TinfoilError.network("no network in this test") }
    ) throws -> EnclaveConnection {
        try EnclaveConnection(
            handle: EnclaveHandle(
                enclave: "enclave.example",
                repo: "org/repo",
                attestationRelay: nil,
                attestor: Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0)
            ),
            transportMode: transportMode,
            baseURL: nil,
            userCacheSecret: "",
            send: send,
            stream: stream
        )
    }

    private func approving() -> FakeNetwork {
        FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) }
    }

    private func assertClosed(_ body: () async throws -> Any, file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await body()
            XCTFail("a closed client must refuse", file: file, line: line)
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertEqual(failure.message, "the client is closed", file: file, line: line)
        } catch {
            XCTFail("expected the closed client's configuration error, got \(error)", file: file, line: line)
        }
    }

    func testAClosedHTTPClientRefusesRequestsAndVerification() async throws {
        for mode in [TransportMode.tls, .ehbp] {
            let network = approving()
            let sent = Box(value: 0)
            let client = try await EnclaveHTTPClient(verifying: connection(network, transportMode: mode, send: { request, _ in
                sent.value += 1
                return (Data(), HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
            }))
            let fetches = network.urls.count

            await client.close()
            await client.close()

            await assertClosed { try await client.data(from: URL(string: "/health")!) }
            await assertClosed { try await client.data(for: URLRequest(url: URL(string: "https://enclave.example/v1/x")!)) }
            await assertClosed { try await client.ensureVerified() }
            await assertClosed { try await client.reverify() }
            XCTAssertEqual(network.urls.count, fetches, "\(mode): nothing is fetched after close")
            XCTAssertEqual(sent.value, 0, "\(mode): nothing is sent after close")
        }
    }

    func testAnOpenAIClientOverAClosedHTTPClientRefuses() async throws {
        for mode in [TransportMode.tls, .ehbp] {
            let network = approving()
            let streamed = Box(value: 0)
            let httpClient = try await EnclaveHTTPClient(verifying: connection(network, transportMode: mode, stream: { _, _ in
                streamed.value += 1
                throw TinfoilError.network("no network in this test")
            }))
            let client = try EnclaveOpenAIClient(httpClient: httpClient, apiKey: "test-key")
            let fetches = network.urls.count

            await httpClient.close()

            await assertClosed { try await client.chats(query: self.query) }
            XCTAssertEqual(network.urls.count, fetches, "\(mode): nothing is fetched after close")
            XCTAssertEqual(streamed.value, 0, "\(mode): nothing is sent after close")
        }
    }

    /// A verification in progress when the client closes ends in an error,
    /// whether its fetch sees the cancellation or its result arrives after
    /// the close, and is never kept.
    func testClosingCancelsAVerificationInProgress() async throws {
        for observesCancellation in [true, false] {
            let entered = AsyncGate()
            let gate = AsyncGate()
            let handle = EnclaveHandle(
                enclave: "enclave.example",
                repo: "org/repo",
                attestationRelay: nil,
                attestor: Attestor(verifier: FakeVerifier(), fetch: { url in
                    await entered.open()
                    await gate.wait()
                    if observesCancellation {
                        try Task.checkCancellation()
                    }
                    return Data(FakeNetwork.document("ok", for: url).utf8)
                }, retryDelay: 0)
            )
            let verification = Task { try await handle.reverify() }
            await entered.wait()

            await handle.close()
            await gate.open()

            do {
                _ = try await verification.value
                XCTFail("the verification in progress must not complete after close")
            } catch is CancellationError {
                XCTAssertTrue(observesCancellation, "Only a fetch that checks sees the cancellation.")
            } catch TinfoilError.configurationError(let failure) {
                XCTAssertEqual(failure.message, "the client is closed")
            } catch {
                XCTFail("unexpected \(error)")
            }
            let current = await handle.current
            XCTAssertNil(current, "A verification finished after close is not kept.")
        }
    }
}
