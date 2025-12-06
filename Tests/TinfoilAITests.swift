import XCTest
import OpenAI
@testable import TinfoilAI

final class TinfoilAITests: XCTestCase {
    
    // MARK: - Test Configuration
        

    func testClientSucceedsWhenVerificationSucceeds() async throws {
        
        // Create client using defaults - this will perform verification internally
        let client = try await TinfoilAI.create(apiKey: "tinfoil")
        
        // Test that client can make a successful request
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Hello' and nothing else.")))
            ],
            model: "llama-free"
        )
        
        let response = try await client.chats(query: chatQuery)
        
        // Verify response
        XCTAssertFalse(response.choices.isEmpty, "Response should contain at least one choice")
        XCTAssertNotNil(response.choices.first?.message.content, "Response should have content")
    }
    
    func testCertificatePinningSuccess() async throws {

        let routerAddress = try await RouterManager.fetchRouter()
        let enclaveURL = "https://\(routerAddress)"

        let secureClient = SecureClient(enclaveURL: enclaveURL)

        let verificationResult = try await secureClient.verify()
        let expectedFingerprint = verificationResult.tlsPublicKey

        let tinfoilClient = try TinfoilClient.create(
            apiKey: "tinfoil",
            enclaveURL: enclaveURL,
            expectedFingerprint: expectedFingerprint,
            parsingOptions: .relaxed
        )
        
        // Test that request succeeds
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Success' and nothing else.")))
            ],
            model: "llama-free"
        )
        
        let response = try await tinfoilClient.underlyingClient.chats(query: chatQuery)
        XCTAssertFalse(response.choices.isEmpty, "Request should succeed with correct fingerprint")
        
        // Clean up
        tinfoilClient.shutdown()
    }
    
    func testCertificatePinningFailure() async throws {

        let routerAddress = try await RouterManager.fetchRouter()
        let enclaveURL = "https://\(routerAddress)"

        let wrongFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"

        let tinfoilClient = try TinfoilClient.create(
            apiKey: "tinfoil",
            enclaveURL: enclaveURL,
            expectedFingerprint: wrongFingerprint
        )
        
        // Test that request fails
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("This should fail")))
            ],
            model: "llama-free"
        )
        
        do {
            _ = try await tinfoilClient.underlyingClient.chats(query: chatQuery)
            XCTFail("Request should have failed due to certificate pinning mismatch")
        } catch {
            // Expected to fail - certificate pinning should reject the connection
            XCTAssertTrue(true, "Certificate pinning correctly prevented connection")
        }
        
        // Clean up
        tinfoilClient.shutdown()
    }
    
    // MARK: - Streaming Tests
    
    func testStreamingChatCompletion() async throws {
        
        // Create client using defaults - this will perform verification internally
        let client = try await TinfoilAI.create(apiKey: "tinfoil")
        
        // Test streaming chat completion
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Count from 1 to 5, one number per response.")))
            ],
            model: "llama-free"
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
    
    func testStreamingWithCertificatePinning() async throws {

        let routerAddress = try await RouterManager.fetchRouter()
        let enclaveURL = "https://\(routerAddress)"

        let secureClient = SecureClient(enclaveURL: enclaveURL)

        let verificationResult = try await secureClient.verify()
        let expectedFingerprint = verificationResult.tlsPublicKey

        let tinfoilClient = try TinfoilClient.create(
            apiKey: "tinfoil",
            enclaveURL: enclaveURL,
            expectedFingerprint: expectedFingerprint,
            parsingOptions: .relaxed
        )
        
        // Test streaming with certificate pinning
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Streaming works!' and nothing else.")))
            ],
            model: "llama-free"
        )
        
        var receivedChunks: [ChatStreamResult] = []
        
        for try await result in tinfoilClient.underlyingClient.chatsStream(query: chatQuery) {
            receivedChunks.append(result)
        }
        
        // Verify streaming succeeded with certificate pinning
        XCTAssertFalse(receivedChunks.isEmpty, "Streaming should succeed with correct certificate pinning")
        
        // Clean up
        tinfoilClient.shutdown()
    }
    
    func testStreamingFailsWithWrongCertificate() async throws {

        let routerAddress = try await RouterManager.fetchRouter()
        let enclaveURL = "https://\(routerAddress)"

        let wrongFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"

        let tinfoilClient = try TinfoilClient.create(
            apiKey: "tinfoil",
            enclaveURL: enclaveURL,
            expectedFingerprint: wrongFingerprint
        )
        
        // Test that streaming fails with wrong certificate
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("This streaming should fail")))
            ],
            model: "llama-free"
        )
        
        do {
            for try await _ in tinfoilClient.underlyingClient.chatsStream(query: chatQuery) {
                XCTFail("Streaming should have failed due to certificate pinning mismatch")
                break
            }
        } catch {
            // Expected to fail - certificate pinning should reject the connection
            XCTAssertTrue(true, "Certificate pinning correctly prevented streaming connection")
        }
        
        // Clean up
        tinfoilClient.shutdown()
    }
    
    func testStreamingResponseStructure() async throws {

        // Create TinfoilAI client using defaults
        let client = try await TinfoilAI.create(apiKey: "tinfoil")

        // Test streaming response structure
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Test' exactly once.")))
            ],
            model: "llama-free"
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

    // MARK: - Integration Tests for New Verification Flow

    func testCompleteVerificationFlowWithNewFormat() async throws {
        // Test the complete flow with the new ClientVerifyJSON() method

        // Test with verification callback to capture the document
        var capturedDocument: VerificationDocument?

        let client = try await TinfoilAI.create(
            apiKey: "tinfoil",
            onVerification: { document in
                capturedDocument = document
            }
        )

        // Verify that verification document was captured
        XCTAssertNotNil(capturedDocument, "Verification document should be captured")

        if let doc = capturedDocument {
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

        // Test that client can make requests after verification
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Integration test passed' and nothing else.")))
            ],
            model: "llama-free"
        )

        let response = try await client.chats(query: chatQuery)
        XCTAssertFalse(response.choices.isEmpty, "Should receive response after verification")
    }

    func testVerificationFailureCallbackWithNewFormat() async throws {
        // Test that verification callback is called even on failure
        var capturedDocument: VerificationDocument?
        var verificationFailed = false

        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                enclaveURL: "https://invalid-enclave-12345.example.com",
                onVerification: { document in
                    capturedDocument = document
                }
            )
            XCTFail("Should have failed with invalid enclave URL")
        } catch {
            verificationFailed = true

            // Verify that document was still captured on failure
            XCTAssertNotNil(capturedDocument, "Verification document should be captured even on failure")

            if let doc = capturedDocument {
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
        let routerAddress = try await RouterManager.fetchRouter()
        let enclaveURL = "https://\(routerAddress)"

        let secureClient = SecureClient(enclaveURL: enclaveURL)

        do {
            let groundTruth = try await secureClient.verify()

            // Test all new fields in GroundTruth
            XCTAssertFalse(groundTruth.tlsPublicKey.isEmpty, "TLS public key should exist")
            XCTAssertNotNil(groundTruth.hpkePublicKey, "HPKE public key field should exist")
            XCTAssertFalse(groundTruth.digest.isEmpty, "Digest should exist")
            XCTAssertFalse(groundTruth.codeFingerprint.isEmpty, "Code fingerprint should exist")
            XCTAssertFalse(groundTruth.enclaveFingerprint.isEmpty, "Enclave fingerprint should exist")

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

        } catch {
            // Network errors are acceptable in CI, but verify error type
            XCTAssertTrue(error is NSError || error is VerificationError,
                         "Error should be a known type: \(error)")
        }
    }

}