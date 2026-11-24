import XCTest
import Foundation
@testable import Tinfoil

/// The OpenAI layer over the attested HTTP clients: where it sends requests,
/// and which API paths it refuses. It does no network I/O of its own.
final class OpenAIClientTests: XCTestCase {
    /// A verified client for enclave.example, sending through `transport`
    private func enclaveClient(_ transport: Transport = .tls) async throws -> EnclaveHTTPClient {
        let network = FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) }
        return try await EnclaveHTTPClient(verifying: EnclaveConnection(
            handle: EnclaveHandle(
                enclave: "enclave.example",
                pin: Pin(repo: "org/repo"),
                attestationRelay: nil,
                attestor: Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0)
            ),
            transportMode: transport.mode,
            baseURL: transport.proxyURL,
            userCacheSecret: ""
        ))
    }

    private func assertConfigurationError(
        _ body: () throws -> Any,
        containing expected: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            guard case TinfoilError.configurationError(let failure) = error else {
                return XCTFail("expected a configuration error, got \(error)", file: file, line: line)
            }
            XCTAssertTrue(failure.message.contains(expected), "\(failure.message) should mention \(expected)", file: file, line: line)
        }
    }

    func testTheBaseURLJoinsTheAPIPathUnderTheEnclaveOrTheProxy() async throws {
        let direct = try await enclaveClient()
        XCTAssertEqual(try OpenAIClient(httpClient: direct, apiKey: "k").baseURL.absoluteString, "https://enclave.example/v1/")
        let custom = try OpenAIClient(httpClient: direct, options: .init(apiPath: "/openai/v1"), apiKey: "k")
        XCTAssertEqual(custom.baseURL.absoluteString, "https://enclave.example/openai/v1/")
        XCTAssertEqual(custom.openAI.configuration.scheme, "https")
        XCTAssertEqual(custom.openAI.configuration.host, "enclave.example")
        XCTAssertEqual(custom.openAI.configuration.port, 443)
        XCTAssertEqual(custom.openAI.configuration.basePath, "/openai/v1")

        for proxy in ["https://proxy.example/relay", "https://proxy.example/relay/"] {
            let proxied = try await enclaveClient(.ehbp(proxyURL: URL(string: proxy)!))
            let client = try OpenAIClient(httpClient: proxied, apiKey: "k")
            XCTAssertEqual(client.baseURL.absoluteString, "https://proxy.example/relay/v1/", proxy)
            XCTAssertEqual(client.openAI.configuration.host, "proxy.example")
            XCTAssertEqual(client.openAI.configuration.basePath, "/relay/v1")
            XCTAssertTrue(client.httpClient === proxied)
        }
    }

    func testInvalidAPIPathsAreRefused() async throws {
        let direct = try await enclaveClient()
        let refused = [
            "", "v1/", "//v1/", "https://other.example/v1/", "/v1?x=1", "/v1?", "/v1#", "/v1/#x",
            "/a/../b", "/a/./b", "/..", "/a/%2e%2e/b", "/a/%2E/b", "/a%2Fb/", "/a%2fb", "/a%zz/", "/a b/",
        ]
        for apiPath in refused {
            assertConfigurationError({ try OpenAIClient(httpClient: direct, options: .init(apiPath: apiPath), apiKey: "k") }, containing: "invalid API path")
        }
        for apiPath in ["/", "/v1", "/v1/", "/openai/v1", "/a%20b/", "/a..b/", "/.well/"] {
            XCTAssertNoThrow(try OpenAIClient(httpClient: direct, options: .init(apiPath: apiPath), apiKey: "k"), apiPath)
        }
    }

    func testAGatewayClientUsesItsURLAndTakesNoAPIPath() async throws {
        let gateway = try await GatewayHTTPClient(options: .init(
            modelPins: ["m": ModelPin(repo: "tinfoilsh/model")],
            url: URL(string: "https://gw.example/openai/v1")!,
            userCacheSecret: "pinned",
            catalog: { [:] }
        ))
        let client = try OpenAIClient(httpClient: gateway, apiKey: "k")
        XCTAssertEqual(client.baseURL.absoluteString, "https://gw.example/openai/v1/")
        XCTAssertEqual(client.openAI.configuration.basePath, "/openai/v1")
        assertConfigurationError({ try OpenAIClient(httpClient: gateway, options: .init(apiPath: "/v1/"), apiKey: "k") }, containing: "already carries the API path")
    }

    func testAMissingAPIKeyIsRefused() async throws {
        let direct = try await enclaveClient()
        assertConfigurationError({ try OpenAIClient(httpClient: direct) }, containing: "pass apiKey or apiKeyProvider")
        XCTAssertNoThrow(try OpenAIClient(httpClient: direct, apiKeyProvider: { "rotating" }))
    }

    func testClosingTheOpenAIClientClosesItsHTTPClient() async throws {
        let direct = try await enclaveClient()
        let client = try OpenAIClient(httpClient: direct, apiKey: "k")
        await client.close()
        do {
            _ = try await direct.ensureVerified()
            XCTFail("a closed client must refuse to verify")
        } catch TinfoilError.configurationError {
        }
    }
}
