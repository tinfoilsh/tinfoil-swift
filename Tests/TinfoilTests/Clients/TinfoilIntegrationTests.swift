import XCTest
@testable import Tinfoil
import OpenAI

final class TinfoilIntegrationTests: XCTestCase {

    func testCreateVerifiesTheDefaultRouter() async throws {
        try requireLiveIntegration()
        // Attestation does not use the API key, so a placeholder is enough to
        // exercise discovery and verification end to end.
        let captured = Box<Result<Verification, TinfoilError>?>(value: nil)

        _ = try await RouterOpenAIClient(
            httpClient: RouterHTTPClient(
                userCacheSecret: "test-secret",
                onVerificationResult: { result in captured.value = result }
            ),
            apiKey: "test-key"
        )

        guard case .success(let verification) = captured.value else {
            return XCTFail("A successful verification should be reported, got \(String(describing: captured.value))")
        }
    }

    func testTheVersionIsReachableThroughTheModule() {
        XCTAssertEqual(Tinfoil.version, TinfoilConstants.sdkVersion)
    }

    /// The key comes only from the caller: the environment is not read.
    func testMissingAPIKeyIgnoresTheEnvironment() async throws {
        let original = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        setenv("TINFOIL_API_KEY", "from-the-environment", 1)
        defer {
            if let original {
                setenv("TINFOIL_API_KEY", original, 1)
            } else {
                unsetenv("TINFOIL_API_KEY")
            }
        }
        do {
            _ = try await Client(apiKey: nil)
            XCTFail("Should have thrown a configuration error")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains("pass apiKey or apiKeyProvider"), failure.message)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testCreateFailsWhenTheAttestationRelayIsUnreachable() async {
        do {
            _ = try await RouterOpenAIClient(
                httpClient: RouterHTTPClient(
                    attestationRelay: "127.0.0.1:9",
                    userCacheSecret: "test-secret"
                ),
                apiKey: "test-key"
            )
            XCTFail("Attestation through an unreachable relay must fail")
        } catch TinfoilError.networkError {
        } catch {
            XCTFail("expected a fetch error, got \(error)")
        }
    }
}
