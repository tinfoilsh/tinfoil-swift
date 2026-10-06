import XCTest
import OpenAI
@testable import TinfoilAI

final class Box<T>: @unchecked Sendable {
    var value: T
    init(value: T) {
        self.value = value
    }
}

final class TinfoilAITests: XCTestCase {
    private static let testUserCacheSecret = "swift-live-integration-cache-secret"

    // MARK: - Test Configuration

    private func getAPIKey() throws -> String? {
        return ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
    }

    private func skipIfNoAPIKey() throws {
        guard try getAPIKey() != nil else {
            throw XCTSkip("Skipping test: TINFOIL_API_KEY environment variable not set")
        }
    }

    func testURLHelpersAcceptHTTPAndHTTPSURLs() throws {
        XCTAssertEqual(try URLHelpers.parseHTTPURL("http://localhost:8080/v1").scheme, "http")
        XCTAssertEqual(try URLHelpers.parseHTTPURL("https://proxy.example.com/v1").scheme, "https")
        XCTAssertEqual(try URLHelpers.parseHTTPURL("proxy.example.com/v1").scheme, "https")
        XCTAssertEqual(try URLHelpers.parseHTTPURL("localhost:8080/v1").port, 8080)
    }

    func testURLHelpersRejectUnsupportedAndMalformedURLs() {
        XCTAssertThrowsError(try URLHelpers.parseHTTPURL("ftp://proxy.example.com/v1"))
        XCTAssertThrowsError(try URLHelpers.parseHTTPURL("mailto:user@example.com"))
        XCTAssertThrowsError(try URLHelpers.parseHTTPURL("file:/tmp/test"))
        XCTAssertThrowsError(try URLHelpers.parseHTTPURL("://"))
    }

    func testGenericURLParserDoesNotRestrictSchemes() throws {
        XCTAssertEqual(try URLHelpers.parseURL("wss://enclave.example.com/realtime").scheme, "wss")
    }

    func testOriginCanonicalizesDefaultPortsCaseAndTrailingDot() {
        XCTAssertEqual(
            URLHelpers.origin(from: "https://ENCLAVE.example.com.:443/v1"),
            URLHelpers.origin(from: "https://enclave.example.com/v1")
        )
        XCTAssertNotEqual(
            URLHelpers.origin(from: "https://enclave.example.com:8443/v1"),
            URLHelpers.origin(from: "https://enclave.example.com/v1")
        )
        XCTAssertNotEqual(
            URLHelpers.origin(from: "https://.enclave.example.com/v1"),
            URLHelpers.origin(from: "https://enclave.example.com/v1")
        )
    }

    func testClientSucceedsWithCacheSecretWhenVerificationSucceeds() async throws {
        try skipIfNoAPIKey()

        let client = try await TinfoilAI.create(
            apiKey: try getAPIKey(),
            userCacheSecret: Self.testUserCacheSecret
        )

        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Hello' and nothing else.")))
            ],
            model: "gpt-oss-120b"
        )

        let response = try await client.chats(query: chatQuery)

        // Verify response
        XCTAssertFalse(response.choices.isEmpty, "Response should contain at least one choice")
        XCTAssertNotNil(response.choices.first?.message.content, "Response should have content")
    }

    func testEHBPEncryptionSuccess() async throws {
        try skipIfNoAPIKey()

        let client = try await TinfoilAI.create(apiKey: try getAPIKey())

        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Success' and nothing else.")))
            ],
            model: "gpt-oss-120b"
        )

        let response = try await client.chats(query: chatQuery)
        XCTAssertFalse(response.choices.isEmpty, "Request should succeed with EHBP encryption")
    }

    func testCreateFailsForAnUnreachableEnclave() async throws {
        do {
            _ = try await TinfoilAI.create(apiKey: "test-key", enclave: "invalid-attestation-12345.example.com")
            XCTFail("Should have failed to fetch attestation from an unreachable enclave")
        } catch TinfoilError.fetchError {
        } catch {
            XCTFail("expected a fetch error, got \(error)")
        }
    }

    // MARK: - Streaming Tests

    func testStreamingChatCompletion() async throws {
        try skipIfNoAPIKey()

        let client = try await TinfoilAI.create(apiKey: try getAPIKey())

        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Count from 1 to 5, one number per response.")))
            ],
            model: "gpt-oss-120b"
        )

        var receivedChunks: [ChatStreamResult] = []
        var accumulatedContent = ""

        for try await result in client.chatsStream(query: chatQuery) {
            receivedChunks.append(result)

            // Accumulate content from delta
            if let choice = result.choices.first,
               let delta = choice.delta.content {
                accumulatedContent += delta
            }
        }

        // Verify streaming response
        XCTAssertFalse(receivedChunks.isEmpty, "Should receive at least one streaming chunk")
        XCTAssertFalse(accumulatedContent.isEmpty, "Should accumulate some content from streaming")

        // Verify we received proper stream structure
        let hasValidChoice = receivedChunks.contains { result in
            !result.choices.isEmpty && result.choices.first?.delta.content != nil
        }
        XCTAssertTrue(hasValidChoice, "Should receive at least one chunk with content")
    }

    func testStreamingWithEHBP() async throws {
        try skipIfNoAPIKey()

        let client = try await TinfoilAI.create(apiKey: try getAPIKey())

        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Streaming works!' and nothing else.")))
            ],
            model: "gpt-oss-120b"
        )

        var receivedChunks: [ChatStreamResult] = []

        for try await result in client.chatsStream(query: chatQuery) {
            receivedChunks.append(result)
        }

        // Verify streaming succeeded with EHBP encryption
        XCTAssertFalse(receivedChunks.isEmpty, "Streaming should succeed with EHBP encryption")
    }

    func testStreamingResponseStructure() async throws {
        try skipIfNoAPIKey()

        let client = try await TinfoilAI.create(apiKey: try getAPIKey())

        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Test' exactly once.")))
            ],
            model: "gpt-oss-120b"
        )

        var hasId = false
        var hasModel = false
        var hasChoices = false
        var hasFinishReason = false

        for try await result in client.chatsStream(query: chatQuery) {
            // Check for required fields in streaming response
            if !result.id.isEmpty {
                hasId = true
            }
            if !result.model.isEmpty {
                hasModel = true
            }
            if !result.choices.isEmpty {
                hasChoices = true

                // Check for finish reason in final chunks
                if let finishReason = result.choices.first?.finishReason {
                    hasFinishReason = true
                    XCTAssertTrue([.stop, .length, .contentFilter].contains(finishReason),
                                 "Finish reason should be a valid value")
                }
            }
        }

        // Verify streaming response structure
        XCTAssertTrue(hasId, "Streaming response should have an ID")
        XCTAssertTrue(hasModel, "Streaming response should have a model")
        XCTAssertTrue(hasChoices, "Streaming response should have choices")
        XCTAssertTrue(hasFinishReason, "Streaming response should eventually have a finish reason")
    }

    // MARK: - Integration Tests for Verification Flow

    func testCompleteVerificationFlow() async throws {
        try skipIfNoAPIKey()

        let captured = Box<Result<Verification, TinfoilError>?>(value: nil)

        let client = try await TinfoilAI.create(
            apiKey: try getAPIKey(),
            onVerification: { result in
                captured.value = result
            }
        )

        guard case .success(let verification) = captured.value else {
            return XCTFail("A successful verification should be reported, got \(String(describing: captured.value))")
        }
        XCTAssertFalse(verification.enclaveHost.isEmpty)
        XCTAssertEqual(verification.hpkePublicKey?.count, 64, "EHBP needs the enclave's HPKE key")
        XCTAssertGreaterThan(verification.freshnessExpiresAt, Date())

        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Integration test passed' and nothing else.")))
            ],
            model: "gpt-oss-120b"
        )

        let response = try await client.chats(query: chatQuery)
        XCTAssertFalse(response.choices.isEmpty, "Should receive response after verification")
    }

    func testVerificationFailureIsReported() async throws {
        let captured = Box<Result<Verification, TinfoilError>?>(value: nil)

        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                enclave: "invalid-attestation-12345.example.com",
                onVerification: { result in
                    captured.value = result
                }
            )
            XCTFail("Should have failed to verify an unreachable enclave")
        } catch {
            guard case .failure(.fetchError) = captured.value else {
                return XCTFail("The failure should be reported, got \(String(describing: captured.value))")
            }
        }
    }

    func testSecureClientVerifiesTheDefaultRouter() async throws {
        let client = try SecureClient()

        let verification: Verification
        do {
            verification = try await client.verify()
        } catch TinfoilError.fetchError(let message) {
            throw XCTSkip("Could not reach Tinfoil's routers: \(message)")
        }

        XCTAssertFalse(verification.enclaveHost.isEmpty)
        XCTAssertEqual(verification.configRepo, TinfoilConstants.defaultGithubRepo)
        XCTAssertFalse(verification.codeDigest.isEmpty)
        XCTAssertEqual(verification.tlsPublicKeyFingerprint.count, 64)
        XCTAssertNotNil(verification.codeMeasurement)
        XCTAssertNotNil(verification.enclaveMeasurement)
        let latest = await client.verification
        XCTAssertEqual(latest, verification)
    }

}
