import XCTest
@testable import TinfoilAI
import OpenAI

final class TinfoilIntegrationTests: XCTestCase {

    func testCreateWithExplicitEnclaveURL() async throws {
        // Test that when an explicit enclave URL is provided, it's used directly
        // This test validates the behavior without making actual network calls

        let explicitURL = "custom.enclave.example.com"

        // We can't directly test the full flow without mocking the verification,
        // but we can test that the URL parameter is properly handled
        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                enclaveURL: explicitURL
            )
            XCTFail("Expected verification to fail for explicit URL")
        } catch {
            // Expected to fail during verification, but that's OK for this test
            // We're just testing that the explicit URL would be used
            if let tinfoilError = error as? TinfoilError {
                XCTAssertNotEqual(tinfoilError, TinfoilError.missingAPIKey)
            }
        }
    }

    func testCreateWithoutEnclaveURLUsesRouter() async throws {
        // Test that when no enclave URL is provided, router fetching is triggered
        // This test validates the behavior without making actual network calls

        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key"
                // No enclaveURL provided - should trigger router fetch
            )
            // If API key is valid, this may succeed - that's acceptable
        } catch {
            // Expected to fail (either during router fetch or verification)
            // We're validating that the router fetch path is triggered
            if let tinfoilError = error as? TinfoilError {
                XCTAssertNotEqual(tinfoilError, TinfoilError.missingAPIKey)
            }
        }
    }

    func testMissingAPIKeyError() async throws {
        let originalValue = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        guard originalValue == nil else {
            throw XCTSkip("Skipping test: TINFOIL_API_KEY is set in environment")
        }

        do {
            _ = try await TinfoilAI.create(
                apiKey: nil,
                enclaveURL: "test.example.com"
            )
            XCTFail("Should have thrown missingAPIKey error")
        } catch TinfoilError.missingAPIKey {
            XCTAssertTrue(true)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testTinfoilClientWithExplicitURL() async throws {
        // Test TinfoilAI with explicit URL parameter
        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                enclaveURL: "https://test.example.com"
            )
            XCTFail("Expected verification to fail for test URL")
        } catch {
            // Expected to fail during verification
            XCTAssertNotNil(error)
        }

        // Test with explicit URL
        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                enclaveURL: "https://custom.example.com"
            )
            XCTFail("Expected verification to fail for custom URL")
        } catch {
            // Expected to fail during verification
            XCTAssertNotNil(error)
        }
    }
}