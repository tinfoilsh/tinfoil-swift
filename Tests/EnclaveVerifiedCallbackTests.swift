import XCTest
import Foundation
import OpenAI
@testable import TinfoilAI

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

    private func handle(
        onEnclaveVerified: @escaping EnclaveVerifiedCallback,
        onVerificationResult: VerificationResultCallback? = nil
    ) throws -> EnclaveHandle {
        let network = FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) }
        return try EnclaveHandle(
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
        )
    }

    private func chat(_ client: TinfoilAI) async throws {
        _ = try await client.chats(query: ChatQuery(messages: [.user(.init(content: .string("Hi")))], model: "test-model"))
    }

    func testCreateFailsWhenTheEnclaveIsRejected() async {
        let reported = Box<Result<Verification, TinfoilError>?>(value: nil)

        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                baseURL: server.baseURL,
                handle: try handle(
                    onEnclaveVerified: { _ in throw Refusal() },
                    onVerificationResult: { reported.value = $0 }
                ),
                userCacheSecret: Self.cacheSecret
            )
            XCTFail("a rejected enclave must not produce a client")
        } catch TinfoilError.enclaveRejected {
        } catch {
            XCTFail("expected a rejection, got \(error)")
        }

        guard case .failure(.enclaveRejected) = reported.value else {
            return XCTFail("the rejection should be reported, got \(String(describing: reported.value))")
        }
        XCTAssertTrue(server.requestStore.requests.isEmpty, "Nothing is sent to a rejected enclave.")
    }

    func testOnEnclaveVerifiedRunsBeforeTheResultIsReported() async throws {
        let events = Recorder<String>()

        _ = try await TinfoilAI.create(
            apiKey: "test-key",
            baseURL: server.baseURL,
            handle: handle(
                onEnclaveVerified: { _ in events.record("enclave verified") },
                onVerificationResult: { _ in events.record("result") }
            ),
            userCacheSecret: Self.cacheSecret
        )

        XCTAssertEqual(events.values, ["enclave verified", "result"])
    }

    func testARejectedRefreshFailsTheRequestWithoutReplaying() async throws {
        let verified = Recorder<String>()
        let client = try await TinfoilAI.create(
            apiKey: "test-key",
            baseURL: server.baseURL,
            handle: handle(onEnclaveVerified: { verification in
                if verified.record(verification.enclaveHost) > 1 {
                    throw Refusal()
                }
            }),
            userCacheSecret: Self.cacheSecret
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
