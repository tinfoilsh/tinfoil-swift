import XCTest
@testable import TinfoilAI
import OpenAI

final class TinfoilIntegrationTests: XCTestCase {

    func testCreateRequiresAnEnclaveForACustomRepo() async {
        do {
            _ = try await TinfoilAI.create(apiKey: "test-key", repo: "org/repo")
            XCTFail("Only Tinfoil's routers can be discovered, so a custom repo needs an enclave")
        } catch TinfoilError.invalidConfiguration {
        } catch {
            XCTFail("expected a configuration error, got \(error)")
        }
    }

    func testCreateVerifiesTheDefaultRouter() async throws {
        try requireLiveIntegration()
        // Attestation does not use the API key, so a placeholder is enough to
        // exercise discovery and verification end to end.
        let captured = Box<Result<Verification, TinfoilError>?>(value: nil)

        _ = try await TinfoilAI.create(
            apiKey: "test-key",
            onVerification: { result in
                captured.value = result
            }
        )

        guard case .success(let verification) = captured.value else {
            return XCTFail("A successful verification should be reported, got \(String(describing: captured.value))")
        }
        XCTAssertFalse(verification.enclaveHost.isEmpty)
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

    func testCreateFailsWhenTheAttestationRelayIsUnreachable() async {
        do {
            _ = try await TinfoilAI.create(
                apiKey: "test-key",
                baseURL: "http://localhost:8080",
                attestationRelay: "127.0.0.1:9"
            )
            XCTFail("Attestation through an unreachable relay must fail")
        } catch TinfoilError.fetchError {
        } catch {
            XCTFail("expected a fetch error, got \(error)")
        }
    }
}
