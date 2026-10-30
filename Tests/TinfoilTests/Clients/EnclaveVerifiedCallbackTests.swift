import XCTest
import Foundation
import OpenAI
import EHBP
@testable import Tinfoil

/// The handle's callbacks end to end: a stand-in attests, and requests go
/// through a real EHBP session to a local server.
final class EnclaveVerifiedCallbackTests: XCTestCase {
    private var server: LocalTestServer!

    /// Pinned so these tests never read or write the persisted secret.
    private static let cacheSecret = "enclave-verified-callback-tests"

    private static let keyConfigProblem = Data(
        #"{"type":"urn:ietf:params:ehbp:error:key-config","title":"stale key"}"#.utf8
    )

    override func setUp() async throws {
        try await super.setUp()
        server = LocalTestServer()
        try server.start()
    }

    override func tearDown() async throws {
        server.stop()
        try await super.tearDown()
    }

    /// An EHBP client for enclave.example that sends to the local server
    private func client(
        onEnclaveVerified: @escaping EnclaveVerifiedCallback = { _ in },
        onVerificationResult: VerificationResultCallback? = nil,
        path: String = ""
    ) async throws -> EnclaveHTTPClient {
        let network = FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) }
        return try await EnclaveHTTPClient(verifying: EnclaveConnection(
            handle: EnclaveHandle(
                enclave: "enclave.example",
                repo: "org/repo",
                attestationRelay: nil,
                attestor: Attestor(
                    verifier: FakeVerifier(),
                    fetch: { try network.fetch($0) },
                    retryDelay: 0,
                    onEnclaveVerified: onEnclaveVerified
                ),
                onVerificationResult: onVerificationResult
            ),
            transportMode: .ehbp,
            baseURL: URL(string: server.baseURL + path)!,
            userCacheSecret: Self.cacheSecret
        ))
    }

    private func chat(_ client: some OpenAICompatibleClient) async throws {
        _ = try await client.chats(query: ChatQuery(messages: [.user(.init(content: .string("Hi")))], model: "test-model"))
    }

    func testRawRequestsReachTheLocalServerOverEHBP() async throws {
        let client = try await client(path: "/api/")
        var request = URLRequest(url: URL(string: "v1/models")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{}".utf8)

        // The stub server can't seal a response, so the request fails;
        // what matters is that it was sent, sealed, where it resolves.
        _ = try? await client.data(for: request)

        XCTAssertEqual(server.requestStore.lastRequest?.path, "/api/v1/models")
    }

    /// The local server's base URL is plain HTTP on 127.0.0.1, which EHBP
    /// accepts on loopback. It authorizes only that exact origin.
    func testALoopbackHTTPBaseURLSendsOnlyToItsOrigin() async throws {
        let client = try await client(path: "/v1/")
        let port = try XCTUnwrap(URLComponents(string: server.baseURL)?.port)
        func post(_ url: String) -> URLRequest {
            var request = URLRequest(url: URL(string: url)!)
            request.httpMethod = "POST"
            request.httpBody = Data("{}".utf8)
            return request
        }

        // The stub server can't seal a response, so the request fails; what
        // matters is that it was sent, sealed, where it resolves.
        _ = try? await client.data(for: post("models"))
        let sent = try XCTUnwrap(server.requestStore.lastRequest)
        XCTAssertEqual(sent.path, "/v1/models")
        XCTAssertNotNil(sent.headers[EHBPProtocol.encapsulatedKeyHeader], "The body is sealed.")
        XCTAssertEqual(sent.headers[URLHelpers.enclaveURLHeaderName], "https://enclave.example")

        for target in [
            "https://127.0.0.1:\(port)/v1/models",
            "http://127.0.0.1:\(port == 65535 ? port - 1 : port + 1)/v1/models",
            "http://localhost:\(port)/v1/models",
            "http://enclave.example/v1/models",
        ] {
            do {
                _ = try await client.data(for: post(target))
                XCTFail("\(target) must be refused")
            } catch TinfoilError.configurationError {
            } catch {
                XCTFail("expected a configuration error for \(target), got \(error)")
            }
        }
        XCTAssertEqual(server.requestStore.requests.count, 1, "Refused requests are not sent.")
    }

    func testTheBasePathComesFromTheNormalizedBaseURL() throws {
        // A base URL without a scheme is read as HTTPS; its path must be read
        // from that same URL, not the raw string.
        for (baseURL, expected) in [("proxy.example/api/", "/api"), ("https://proxy.example/api/", "/api"), ("proxy.example", "/v1")] {
            let openAI = try OpenAI.sealed(
                apiKey: "test-key",
                apiKeyProvider: nil,
                baseURL: baseURL,
                session: EHBPURLSession(baseURL: baseURL, verifiedState: EHBPVerifiedState(endpoint: EHBPVerifiedEndpoint(enclaveURL: "https://enclave.example", publicKey: Data(repeating: 1, count: 32))), userCacheSecret: ""),
                streamingFactory: EHBPURLSessionFactory(baseURL: baseURL, verifiedState: EHBPVerifiedState(endpoint: EHBPVerifiedEndpoint(enclaveURL: "https://enclave.example", publicKey: Data(repeating: 1, count: 32))), userCacheSecret: ""),
                parsingOptions: .relaxed,
                customHeaders: [:],
                tinfoilEvents: []
            )
            XCTAssertEqual(openAI.configuration.host, "proxy.example", baseURL)
            XCTAssertEqual(openAI.configuration.basePath, expected, baseURL)
        }
    }

    func testOpenAIRequestsKeepTheBaseURLsPath() async throws {
        for (path, expected) in [("", "/v1/chat/completions"), ("/api/", "/api/chat/completions")] {
            let client = try await EnclaveOpenAIClient(httpClient: client(path: path), apiKey: "test-key")
            // The stub server can't seal a response, so the request fails;
            // what matters is where it was sent.
            _ = try? await chat(client)
            XCTAssertEqual(server.requestStore.lastRequest?.path, expected, "base URL path \"\(path)\"")
        }
    }

    func testCreateFailsWhenTheEnclaveIsRejected() async {
        let reported = Box<Result<Verification, TinfoilError>?>(value: nil)

        do {
            _ = try await EnclaveOpenAIClient(
                httpClient: try client(
                    onEnclaveVerified: { _ in throw Refusal() },
                    onVerificationResult: { reported.value = $0 }
                ),
                apiKey: "test-key"
            )
            XCTFail("a rejected enclave must not produce a client")
        } catch let error as TinfoilError where error.isRefusal {
        } catch {
            XCTFail("expected the callback's rejection, got \(error)")
        }

        guard case .failure(let error) = reported.value, error.isRefusal else {
            return XCTFail("the rejection should be reported, got \(String(describing: reported.value))")
        }
        XCTAssertTrue(server.requestStore.requests.isEmpty, "Nothing is sent to a rejected enclave.")
    }

    func testOnEnclaveVerifiedRunsBeforeTheResultIsReported() async throws {
        let events = Recorder<String>()

        _ = try await EnclaveOpenAIClient(
            httpClient: client(
                onEnclaveVerified: { _ in events.record("enclave verified") },
                onVerificationResult: { _ in events.record("result") }
            ),
            apiKey: "test-key"
        )

        XCTAssertEqual(events.values, ["enclave verified", "result"])
    }

    func testARejectedRefreshFailsTheRequestWithoutReplaying() async throws {
        let verified = Recorder<String>()
        let client = try await EnclaveOpenAIClient(
            httpClient: client(onEnclaveVerified: { verification in
                if verified.record(verification.codeDigest) > 1 {
                    throw Refusal()
                }
            }),
            apiKey: "test-key"
        )
        // The enclave rejects the key, so the client re-verifies before
        // replaying; the rejected re-verification must end the request.
        server.responseStatusCode = 422
        server.responseContentType = "application/problem+json"
        server.includeResponseNonce = false
        server.responseBody = Self.keyConfigProblem

        do {
            try await chat(client)
            XCTFail("a rejected refresh must fail the request")
        } catch {
            XCTAssertTrue(String(describing: error).contains("onEnclaveVerified rejected"), "unexpected error \(error)")
        }

        XCTAssertEqual(verified.values.count, 2, "The refreshed enclave was passed to the callback.")
        XCTAssertEqual(server.requestStore.requests.count, 1, "Nothing is replayed after the rejected refresh.")
    }
}
