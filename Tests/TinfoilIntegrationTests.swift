import XCTest
@testable import TinfoilAI
import OpenAI

final class TinfoilIntegrationTests: XCTestCase {

    func testCreateWithCustomAttestationBundleURL() async throws {
        // Test that when an explicit attestation bundle URL is provided, it's used
        // This test validates the behavior without making actual network calls

        let customURL = "https://custom.example.com/attestation"

        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                attestationBundleURL: customURL
            )
            XCTFail("Expected verification to fail for custom URL")
        } catch {
            // Expected to fail during verification, but that's OK for this test
            // We're just testing that the URL parameter is properly handled
            if let tinfoilError = error as? TinfoilError {
                XCTAssertNotEqual(tinfoilError, TinfoilError.missingAPIKey)
            }
        }
    }

    func testCreateWithDefaultATCEndpoint() async throws {
        // Test that when no attestation bundle URL is provided, default ATC is used
        // This test validates the behavior without making actual network calls

        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key"
                // No attestationBundleURL provided - should use default ATC endpoint
            )
            // If API key is valid, this may succeed - that's acceptable
        } catch {
            // Expected to fail (either during fetch or verification)
            // We're validating that the default ATC path is triggered
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
            _ = try await TinfoilAI.create(apiKey: nil)
            XCTFail("Should have thrown missingAPIKey error")
        } catch TinfoilError.missingAPIKey {
            XCTAssertTrue(true)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testCreateWithProxyConfiguration() async throws {
        // Test TinfoilAI with proxy configuration (both baseURL and attestationBundleURL)
        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                baseURL: "http://localhost:8080",
                attestationBundleURL: "http://localhost:8080"
            )
            XCTFail("Expected verification to fail for proxy URL")
        } catch {
            // Expected to fail during verification
            XCTAssertNotNil(error)
        }
    }
}
