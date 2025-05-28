import XCTest
import OpenAI
@testable import TinfoilAI

final class TinfoilAITests: XCTestCase {
    
    // MARK: - Test Configuration
    
    private let testEnclaveURL = "https://llama3-3-70b.model.tinfoil.sh"
    private let testGithubRepo = "tinfoilsh/confidential-llama3-3-70b"
    
    // MARK: - Essential Tests
    
    func testClientSucceedsWhenVerificationSucceeds() async throws {
        let apiKey = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] ?? ""
        
        // Create TinfoilAI client - this will perform verification internally
        let tinfoil = try await TinfoilAI(
            apiKey: apiKey,
            githubRepo: testGithubRepo,
            enclaveURL: testEnclaveURL
        )
        
        // Test that client can make a successful request
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Hello' and nothing else.")))
            ],
            model: "llama3-3-70b"
        )
        
        let response = try await tinfoil.client.chats(query: chatQuery)
        
        // Verify response
        XCTAssertFalse(response.choices.isEmpty, "Response should contain at least one choice")
        XCTAssertNotNil(response.choices.first?.message.content, "Response should have content")
    }
    
    func testCertificatePinningSuccess() async throws {
        let apiKey = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] ?? ""
        
        // Get the correct fingerprint from verification
        let secureClient = SecureClient(
            githubRepo: testGithubRepo,
            enclaveURL: testEnclaveURL
        )
        
        let verificationResult = try await secureClient.verify()
        let expectedFingerprint = verificationResult.publicKeyFP
        
        // Create client with correct fingerprint and relaxed parsing
        let tinfoilClient = try TinfoilClient.create(
            apiKey: apiKey,
            enclaveURL: testEnclaveURL,
            expectedFingerprint: expectedFingerprint,
            parsingOptions: .relaxed
        )
        
        // Test that request succeeds
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Success' and nothing else.")))
            ],
            model: "llama3-3-70b"
        )
        
        let response = try await tinfoilClient.underlyingClient.chats(query: chatQuery)
        XCTAssertFalse(response.choices.isEmpty, "Request should succeed with correct fingerprint")
        
        // Clean up
        tinfoilClient.shutdown()
    }
    
    func testCertificatePinningFailure() async throws {
        let apiKey = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] ?? ""
        
        // Create client with wrong fingerprint
        let wrongFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
        
        let tinfoilClient = try TinfoilClient.create(
            apiKey: apiKey,
            enclaveURL: testEnclaveURL,
            expectedFingerprint: wrongFingerprint
        )
        
        // Test that request fails
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("This should fail")))
            ],
            model: "llama3-3-70b"
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
        let apiKey = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] ?? ""
        
        // Create TinfoilAI client - this will perform verification internally
        let tinfoil = try await TinfoilAI(
            apiKey: apiKey,
            githubRepo: testGithubRepo,
            enclaveURL: testEnclaveURL
        )
        
        // Test streaming chat completion
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Count from 1 to 5, one number per response.")))
            ],
            model: "llama3-3-70b"
        )
        
        var receivedChunks: [ChatStreamResult] = []
        var accumulatedContent = ""
        
        for try await result in tinfoil.client.chatsStream(query: chatQuery) {
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
        let apiKey = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] ?? ""
        
        // Get the correct fingerprint from verification
        let secureClient = SecureClient(
            githubRepo: testGithubRepo,
            enclaveURL: testEnclaveURL
        )
        
        let verificationResult = try await secureClient.verify()
        let expectedFingerprint = verificationResult.publicKeyFP
        
        // Create client with correct fingerprint and relaxed parsing
        let tinfoilClient = try TinfoilClient.create(
            apiKey: apiKey,
            enclaveURL: testEnclaveURL,
            expectedFingerprint: expectedFingerprint,
            parsingOptions: .relaxed
        )
        
        // Test streaming with certificate pinning
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Streaming works!' and nothing else.")))
            ],
            model: "llama3-3-70b"
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
        let apiKey = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] ?? ""
        
        // Create client with wrong fingerprint
        let wrongFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
        
        let tinfoilClient = try TinfoilClient.create(
            apiKey: apiKey,
            enclaveURL: testEnclaveURL,
            expectedFingerprint: wrongFingerprint
        )
        
        // Test that streaming fails with wrong certificate
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("This streaming should fail")))
            ],
            model: "llama3-3-70b"
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
        let apiKey = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] ?? ""
        
        // Create TinfoilAI client
        let tinfoil = try await TinfoilAI(
            apiKey: apiKey,
            githubRepo: testGithubRepo,
            enclaveURL: testEnclaveURL
        )
        
        // Test streaming response structure
        let chatQuery = ChatQuery(
            messages: [
                .user(.init(content: .string("Say 'Test' exactly once.")))
            ],
            model: "llama3-3-70b"
        )
        
        var hasId = false
        var hasModel = false
        var hasChoices = false
        var hasFinishReason = false
        
        for try await result in tinfoil.client.chatsStream(query: chatQuery) {
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
} 