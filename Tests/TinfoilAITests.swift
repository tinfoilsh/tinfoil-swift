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

    // MARK: - Test Configuration

    private func getAPIKey() throws -> String? {
        return ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
    }

    private func skipIfNoAPIKey() throws {
        guard try getAPIKey() != nil else {
            throw XCTSkip("Skipping test: TINFOIL_API_KEY environment variable not set")
        }
    }

    func testClientSucceedsWhenVerificationSucceeds() async throws {
        try skipIfNoAPIKey()

        let client = try await TinfoilAI.create(apiKey: try getAPIKey())

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

    func testVerificationFailureWithInvalidAttestationURL() async throws {
        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                attestationBundleURL: "https://invalid-attestation-12345.example.com"
            )
            XCTFail("Should have failed with invalid attestation URL")
        } catch {
            // Expected - verification should reject invalid attestation URL
            // Error may be VerificationError or NSError from Go bindings
            XCTAssertNotNil(error)
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

    func testCompleteVerificationFlowWithNewFormat() async throws {
        try skipIfNoAPIKey()

        let capturedDocument = Box<VerificationDocument?>(value: nil)

        let client = try await TinfoilAI.create(
            apiKey: try getAPIKey(),
            onVerification: { document in
                capturedDocument.value = document
            }
        )

        // Verify that verification document was captured
        XCTAssertNotNil(capturedDocument.value, "Verification document should be captured")

        if let doc = capturedDocument.value {
            // Verify document has all required fields from new format
            XCTAssertFalse(doc.tlsPublicKey.isEmpty, "TLS public key should be present")
            XCTAssertFalse(doc.codeFingerprint.isEmpty, "Code fingerprint should be present")
            XCTAssertFalse(doc.enclaveFingerprint.isEmpty, "Enclave fingerprint should be present")
            XCTAssertFalse(doc.selectedRouterEndpoint.isEmpty, "Selected router endpoint should be present")
            XCTAssertTrue(doc.securityVerified, "Security should be verified for successful flow")

            // Verify all steps are successful
            if doc.steps.fetchDigest.status == .success,
               doc.steps.verifyCode.status == .success,
               doc.steps.verifyEnclave.status == .success,
               doc.steps.compareMeasurements.status == .success {
                XCTAssertTrue(true, "All verification steps should be successful")
            } else {
                XCTFail("Not all verification steps were successful")
            }
        }

        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Integration test passed' and nothing else.")))
            ],
            model: "gpt-oss-120b"
        )

        let response = try await client.chats(query: chatQuery)
        XCTAssertFalse(response.choices.isEmpty, "Should receive response after verification")
    }

    func testVerificationFailureCallbackWithNewFormat() async throws {
        let capturedDocument = Box<VerificationDocument?>(value: nil)
        var verificationFailed = false

        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                attestationBundleURL: "https://invalid-attestation-12345.example.com",
                onVerification: { document in
                    capturedDocument.value = document
                }
            )
            XCTFail("Should have failed with invalid attestation URL")
        } catch {
            verificationFailed = true

            // Verify that document was still captured on failure
            XCTAssertNotNil(capturedDocument.value, "Verification document should be captured even on failure")

            if let doc = capturedDocument.value {
                XCTAssertFalse(doc.securityVerified, "Security should not be verified on failure")

                // At least one step should be failed or pending
                var hasNonSuccessStep = false

                if doc.steps.fetchDigest.status != .success {
                    hasNonSuccessStep = true
                }

                if doc.steps.verifyCode.status != .success {
                    hasNonSuccessStep = true
                }

                if doc.steps.verifyEnclave.status != .success {
                    hasNonSuccessStep = true
                }

                if doc.steps.compareMeasurements.status != .success {
                    hasNonSuccessStep = true
                }

                XCTAssertTrue(hasNonSuccessStep, "At least one step should not be successful on failure")
            }
        }

        XCTAssertTrue(verificationFailed, "Verification should have failed")
    }

    func testNewGroundTruthFieldsIntegration() async throws {
        // Use SecureClient with default attestation bundle flow
        let secureClient = SecureClient(githubRepo: TinfoilConstants.defaultGithubRepo)

        do {
            let groundTruth = try await secureClient.verify()

            // Test all new fields in GroundTruth
            XCTAssertFalse(groundTruth.tlsPublicKey.isEmpty, "TLS public key should exist")
            XCTAssertNotNil(groundTruth.hpkePublicKey, "HPKE public key field should exist")
            XCTAssertFalse(groundTruth.digest.isEmpty, "Digest should exist")
            XCTAssertFalse(groundTruth.codeFingerprint.isEmpty, "Code fingerprint should exist")
            XCTAssertFalse(groundTruth.enclaveFingerprint.isEmpty, "Enclave fingerprint should exist")

            // Verify enclave host is populated from attestation bundle
            XCTAssertNotNil(groundTruth.enclaveHost, "Enclave host should exist")
            XCTAssertFalse(groundTruth.enclaveHost?.isEmpty ?? true, "Enclave host should not be empty")

            // Verify measurements
            if let codeMeasurement = groundTruth.codeMeasurement {
                XCTAssertFalse(codeMeasurement.type.isEmpty, "Code measurement type should exist")
                XCTAssertFalse(codeMeasurement.registers.isEmpty, "Code measurement should have registers")
            }

            if let enclaveMeasurement = groundTruth.enclaveMeasurement {
                XCTAssertFalse(enclaveMeasurement.type.isEmpty, "Enclave measurement type should exist")
                XCTAssertFalse(enclaveMeasurement.registers.isEmpty, "Enclave measurement should have registers")
            }

            // Hardware measurement may or may not exist depending on platform
            if let hwMeasurement = groundTruth.hardwareMeasurement {
                XCTAssertFalse(hwMeasurement.id.isEmpty, "Hardware ID should exist if present")
                XCTAssertFalse(hwMeasurement.mrtd.isEmpty, "MRTD should exist if present")
                XCTAssertFalse(hwMeasurement.rtmr0.isEmpty, "RTMR0 should exist if present")
            }

        } catch is VerificationError {
            // Verification errors are acceptable (may occur due to network issues in CI)
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

}
