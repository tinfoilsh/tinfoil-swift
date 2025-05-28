import XCTest
import OpenAI
@testable import TinfoilKit

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
} 