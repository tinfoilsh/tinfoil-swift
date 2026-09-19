import XCTest
@testable import TinfoilAI
import Tinfoil

final class TinfoilIntegrationTests: XCTestCase {
    private static let liveEnclave = "inference.tinfoil.sh"
    private static let customRepo = "owner/repo"
    private static let testCacheSecret = "swift-v3-integration-cache-secret"

    func testExplicitEnclavePreservesHostPortAndRepository() throws {
        let client = SecureClient(githubRepo: Self.customRepo, enclaveURL: "https://enclave.example:8443")
        XCTAssertNil(client.verifiedEnclaveURL)
        let verifier = try client.makeGoClient(host: "enclave.example:8443")
        XCTAssertEqual(verifier.enclave(), "enclave.example:8443")
        XCTAssertEqual(verifier.repo(), Self.customRepo)
        XCTAssertNil(verifier.groundTruth())
    }

    func testCustomRepositoryCannotUseDefaultDiscovery() async {
        let client = SecureClient(githubRepo: Self.customRepo)
        do {
            _ = try await client.verify()
            XCTFail("A custom repository needs an explicit enclave")
        } catch {
            XCTAssertEqual(error.localizedDescription, "A custom githubRepo requires enclaveURL")
            XCTAssertNil(client.verifiedGroundTruth)
            XCTAssertNil(client.verifiedEnclaveURL)
            XCTAssertEqual(client.verificationDocument?.securityVerified, false)
            XCTAssertEqual(client.verificationDocument?.steps.fetchDigest.status, .skipped)
            XCTAssertEqual(client.verificationDocument?.steps.verifyCode.status, .pending)
            XCTAssertEqual(client.verificationDocument?.steps.otherError?.status, .failed)
        }
    }

    func testPinnedFactoryCannotFallBackToDiscovery() {
        let client = SecureClient(
            enclaveURL: "https://enclave.example",
            pinnedMeasurement: AttestationMeasurement(
                type: "https://tinfoil.sh/predicate/sev-snp-guest/v2",
                registers: [String(repeating: "ab", count: 48)]
            )
        )
        XCTAssertThrowsError(try client.makeGoClient(host: nil)) { error in
            XCTAssertEqual(error.localizedDescription, "pinnedMeasurement requires enclaveURL")
        }
    }

    func testUnverifiedFallbackIsVerifiedBeforeUse() throws {
        let fallback = try XCTUnwrap(ClientNewSecureClient(Self.liveEnclave, TinfoilConstants.defaultGithubRepo))
        XCTAssertNil(fallback.groundTruth())
        try SecureClient.verifyIfNeeded(fallback)
        let verified = try XCTUnwrap(fallback.groundTruth())
        XCTAssertFalse(verified.codeFingerprint.isEmpty)
        XCTAssertEqual(verified.codeFingerprint, verified.enclaveFingerprint)

        // A factory-selected router that was already verified is not fetched twice.
        let verifiedAt = verified.verifiedAt
        try SecureClient.verifyIfNeeded(fallback)
        XCTAssertEqual(fallback.groundTruth()?.verifiedAt, verifiedAt)
    }

    func testInvalidFallbackNeverBecomesVerified() throws {
        // A malformed authority fails request construction without network access.
        let fallback = try XCTUnwrap(ClientNewSecureClient("invalid host", TinfoilConstants.defaultGithubRepo))
        XCTAssertThrowsError(try SecureClient.verifyIfNeeded(fallback))
        XCTAssertNil(fallback.groundTruth())
    }

    func testCreateWithDefaultV3Discovery() async throws {
        let captured = Box<VerificationDocument?>(value: nil)
        _ = try await TinfoilAI.create(
            apiKey: "test-key",
            userCacheSecret: Self.testCacheSecret,
            onVerification: { captured.value = $0 }
        )
        let document = try XCTUnwrap(captured.value)
        XCTAssertTrue(document.securityVerified)
        XCTAssertEqual(document.configRepo, TinfoilConstants.defaultGithubRepo)
        XCTAssertFalse(document.enclaveHost.isEmpty)
        XCTAssertEqual(document.codeFingerprint, document.enclaveFingerprint)
        XCTAssertEqual(document.steps.fetchDigest.status, .skipped)
        XCTAssertEqual(document.steps.verifyCode.status, .success)
    }

    func testRequestProxyIsNotUsedAsAttestationEndpoint() async throws {
        let captured = Box<VerificationDocument?>(value: nil)
        // No application request is sent. Creation must succeed even though the
        // local request proxy is unavailable; attestation goes to the enclave.
        _ = try await TinfoilAI.create(
            apiKey: "test-key",
            baseURL: "http://127.0.0.1:1",
            userCacheSecret: Self.testCacheSecret,
            onVerification: { captured.value = $0 }
        )
        let document = try XCTUnwrap(captured.value)
        XCTAssertTrue(document.securityVerified)
        XCTAssertFalse(document.enclaveHost.isEmpty)
        XCTAssertNotEqual(document.enclaveHost, "127.0.0.1:1")
        XCTAssertEqual(document.codeFingerprint, document.enclaveFingerprint)
    }

    func testMissingAPIKeyError() async throws {
        guard ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] == nil else {
            throw XCTSkip("TINFOIL_API_KEY is set in the environment")
        }
        do {
            _ = try await TinfoilAI.create(apiKey: nil)
            XCTFail("Should have thrown missingAPIKey")
        } catch TinfoilError.missingAPIKey {
        }
    }
}
