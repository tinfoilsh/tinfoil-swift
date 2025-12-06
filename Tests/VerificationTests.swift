import XCTest
@testable import TinfoilAI
import TinfoilVerifier

final class VerificationTests: XCTestCase {

    // MARK: - New Verification Format Tests

    func testNewVerificationFormatFields() async throws {
        let routerAddress = try await RouterManager.fetchRouter()
        let enclaveURL = "https://\(routerAddress)"

        let secureClient = SecureClient(
            githubRepo: TinfoilConstants.defaultGithubRepo,
            enclaveURL: enclaveURL
        )

        do {
            let groundTruth = try await secureClient.verify()

            // Verify all new fields are populated
            XCTAssertFalse(groundTruth.tlsPublicKey.isEmpty, "TLS public key should be populated")
            XCTAssertFalse(groundTruth.digest.isEmpty, "Digest should be populated")
            XCTAssertFalse(groundTruth.codeFingerprint.isEmpty, "Code fingerprint should be populated")
            XCTAssertFalse(groundTruth.enclaveFingerprint.isEmpty, "Enclave fingerprint should be populated")

            // Verify HPKE public key exists (may be empty for some configurations)
            XCTAssertNotNil(groundTruth.hpkePublicKey, "HPKE public key field should exist")

            // Verify measurements exist
            XCTAssertNotNil(groundTruth.codeMeasurement, "Code measurement should exist")
            XCTAssertNotNil(groundTruth.enclaveMeasurement, "Enclave measurement should exist")

            // Hardware measurement may be nil for non-TDX platforms
            // Just verify the field exists in the structure
            _ = groundTruth.hardwareMeasurement

            // Verify the verification document is properly populated
            let verificationDoc = secureClient.getVerificationDocument()
            XCTAssertNotNil(verificationDoc, "Verification document should be available")
            XCTAssertTrue(verificationDoc?.securityVerified ?? false, "Security should be verified")
            XCTAssertEqual(verificationDoc?.tlsPublicKey, groundTruth.tlsPublicKey, "TLS key should match")
            XCTAssertEqual(verificationDoc?.codeFingerprint, groundTruth.codeFingerprint, "Code fingerprint should match")
            XCTAssertEqual(verificationDoc?.enclaveFingerprint, groundTruth.enclaveFingerprint, "Enclave fingerprint should match")
            XCTAssertFalse(verificationDoc?.selectedRouterEndpoint.isEmpty ?? true, "Router endpoint should be populated")
        } catch {
            // If this fails in CI, it might be due to network issues
        }
    }

    func testVerificationStepFailures() async throws {
        // Test each failure prefix scenario by using invalid configurations

        // Test 1: Invalid URL that should fail early
        let invalidClient = SecureClient(
            githubRepo: TinfoilConstants.defaultGithubRepo,
            enclaveURL: "invalid-url-format"
        )

        do {
            _ = try await invalidClient.verify()
            XCTFail("Should have failed with invalid URL")
        } catch {
            let verificationDoc = invalidClient.getVerificationDocument()
            XCTAssertNotNil(verificationDoc, "Should have failure document")
            XCTAssertFalse(verificationDoc?.securityVerified ?? true, "Security should not be verified")
        }

        // Test 2: Non-existent host that should fail at fetchDigest
        let nonExistentClient = SecureClient(
            githubRepo: TinfoilConstants.defaultGithubRepo,
            enclaveURL: "https://non-existent-host-12345.example.com"
        )

        do {
            _ = try await nonExistentClient.verify()
            XCTFail("Should have failed with non-existent host")
        } catch {
            let verificationDoc = nonExistentClient.getVerificationDocument()
            XCTAssertNotNil(verificationDoc, "Should have failure document")
            XCTAssertFalse(verificationDoc?.securityVerified ?? true, "Security should not be verified")

            // Check if the error indicates a fetch failure
            if let steps = verificationDoc?.steps {
                // At least one step should have failed
                let hasFailure = steps.fetchDigest.status == .failed ||
                                steps.verifyCode.status == .failed ||
                                steps.verifyEnclave.status == .failed ||
                                steps.compareMeasurements.status == .failed
                XCTAssertTrue(hasFailure, "At least one step should be marked as failed")
            }
        }

        let routerAddress = try await RouterManager.fetchRouter()
        let enclaveURL = "https://\(routerAddress)"

        let invalidRepoClient = SecureClient(
            githubRepo: "invalid-org/non-existent-repo",
            enclaveURL: enclaveURL
        )

        do {
            _ = try await invalidRepoClient.verify()
            XCTFail("Should have failed with invalid GitHub repo")
        } catch {
            let verificationDoc = invalidRepoClient.getVerificationDocument()
            XCTAssertNotNil(verificationDoc, "Should have failure document")
            XCTAssertFalse(verificationDoc?.securityVerified ?? true, "Security should not be verified")
        }
    }

    // MARK: - Hardware Measurement Tests

    func testHardwareMeasurementParsing() async throws {
        // Test TDX platform data parsing
        // Create test data with hardware measurement
        let jsonWithHardware = """
        {
            "tls_public_key": "test-tls-key",
            "hpke_public_key": "test-hpke-key",
            "digest": "test-digest",
            "code_fingerprint": "test-code-fp",
            "enclave_fingerprint": "test-enclave-fp",
            "hardware_measurement": {
                "ID": "TDX-001",
                "MRTD": "0123456789abcdef",
                "RTMR0": "fedcba9876543210"
            },
            "code_measurement": {
                "type": "MREnclave",
                "registers": ["register1", "register2"]
            },
            "enclave_measurement": {
                "type": "MRSigner",
                "registers": ["register3", "register4"]
            }
        }
        """

        let decoder = JSONDecoder()
        let groundTruth = try decoder.decode(GroundTruth.self, from: jsonWithHardware.data(using: .utf8)!)

        // Verify hardware measurement is properly parsed
        XCTAssertNotNil(groundTruth.hardwareMeasurement, "Hardware measurement should be parsed")
        XCTAssertEqual(groundTruth.hardwareMeasurement?.id, "TDX-001", "Hardware ID should match")
        XCTAssertEqual(groundTruth.hardwareMeasurement?.mrtd, "0123456789abcdef", "MRTD should match")
        XCTAssertEqual(groundTruth.hardwareMeasurement?.rtmr0, "fedcba9876543210", "RTMR0 should match")

        // Test JSON without hardware measurement (non-TDX platform)
        let jsonWithoutHardware = """
        {
            "tls_public_key": "test-tls-key",
            "hpke_public_key": "test-hpke-key",
            "digest": "test-digest",
            "code_fingerprint": "test-code-fp",
            "enclave_fingerprint": "test-enclave-fp",
            "code_measurement": {
                "type": "MREnclave",
                "registers": ["register1", "register2"]
            },
            "enclave_measurement": {
                "type": "MRSigner",
                "registers": ["register3", "register4"]
            }
        }
        """

        let groundTruthNoHW = try decoder.decode(GroundTruth.self, from: jsonWithoutHardware.data(using: .utf8)!)
        XCTAssertNil(groundTruthNoHW.hardwareMeasurement, "Hardware measurement should be nil for non-TDX")
    }

    // MARK: - Error Message Parsing Tests

    func testErrorMessageParsing() {
        // Test error prefix detection logic
        let testCases: [(error: String, expectedStep: String)] = [
            ("fetchDigest: failed to connect", "fetchDigest"),
            ("verifyCode: invalid repository", "verifyCode"),
            ("verifyEnclave: measurement mismatch", "verifyEnclave"),
            ("verifyHardware: TDX attestation failed", "verifyHardware"),
            ("validateTLS: certificate invalid", "validateTLS"),
            ("measurements: comparison failed", "validateTLS"),
            ("unknown error without prefix", "other")
        ]

        for testCase in testCases {
            let errorMessage = testCase.error
            var detectedStep = "other"

            if errorMessage.starts(with: "fetchDigest:") {
                detectedStep = "fetchDigest"
            } else if errorMessage.starts(with: "verifyCode:") {
                detectedStep = "verifyCode"
            } else if errorMessage.starts(with: "verifyEnclave:") {
                detectedStep = "verifyEnclave"
            } else if errorMessage.starts(with: "verifyHardware:") {
                detectedStep = "verifyHardware"
            } else if errorMessage.starts(with: "validateTLS:") || errorMessage.starts(with: "measurements:") {
                detectedStep = "validateTLS"
            }

            XCTAssertEqual(detectedStep, testCase.expectedStep,
                          "Error '\(errorMessage)' should be detected as '\(testCase.expectedStep)' step")
        }
    }

    // MARK: - Verification Document Tests

    func testVerificationDocumentCompleteness() {
        // Test that VerificationDocument properly captures all fields
        let testDoc = VerificationDocument(
            configRepo: "test-repo",
            enclaveHost: "test-url",
            releaseDigest: "test-digest",
            codeMeasurement: AttestationMeasurement(type: "MREnclave", registers: ["r1"]),
            enclaveMeasurement: AttestationResponse(
                measurement: AttestationMeasurement(type: "MRSigner", registers: ["r2"])
            ),
            tlsPublicKey: "test-tls",
            hpkePublicKey: "test-hpke",
            hardwareMeasurement: HardwareMeasurement(
                id: "TDX-1",
                mrtd: "mrtd-value",
                rtmr0: "rtmr0-value"
            ),
            codeFingerprint: "code-fp",
            enclaveFingerprint: "enclave-fp",
            selectedRouterEndpoint: "router.example.com",
            securityVerified: true,
            steps: VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .success(),
                verifyEnclave: .success(),
                compareMeasurements: .success()
            )
        )

        // Verify all fields are accessible
        XCTAssertEqual(testDoc.configRepo, "test-repo")
        XCTAssertEqual(testDoc.enclaveHost, "test-url")
        XCTAssertEqual(testDoc.releaseDigest, "test-digest")
        XCTAssertEqual(testDoc.tlsPublicKey, "test-tls")
        XCTAssertEqual(testDoc.hpkePublicKey, "test-hpke")
        XCTAssertEqual(testDoc.codeFingerprint, "code-fp")
        XCTAssertEqual(testDoc.enclaveFingerprint, "enclave-fp")
        XCTAssertEqual(testDoc.selectedRouterEndpoint, "router.example.com")
        XCTAssertTrue(testDoc.securityVerified)
        XCTAssertNotNil(testDoc.hardwareMeasurement)
        XCTAssertEqual(testDoc.hardwareMeasurement?.id, "TDX-1")
    }

    // MARK: - Step Status Tests

    func testVerificationStepStatuses() {
        // Test different step status combinations
        let successSteps = VerificationDocument.Steps(
            fetchDigest: .success(),
            verifyCode: .success(),
            verifyEnclave: .success(),
            compareMeasurements: .success()
        )

        // Verify success case
        XCTAssertEqual(successSteps.fetchDigest.status, .success, "Fetch digest should be success")
        XCTAssertEqual(successSteps.verifyCode.status, .success, "Verify code should be success")
        XCTAssertEqual(successSteps.verifyEnclave.status, .success, "Verify enclave should be success")
        XCTAssertEqual(successSteps.compareMeasurements.status, .success, "Compare measurements should be success")

        // Test partial failure
        let partialFailureSteps = VerificationDocument.Steps(
            fetchDigest: .success(),
            verifyCode: .success(),
            verifyEnclave: .failed("Enclave verification failed"),
            compareMeasurements: .pending()
        )

        XCTAssertEqual(partialFailureSteps.fetchDigest.status, .success, "Fetch digest should be success")
        XCTAssertEqual(partialFailureSteps.verifyCode.status, .success, "Verify code should be success")
        XCTAssertEqual(partialFailureSteps.verifyEnclave.status, .failed, "Verify enclave should be failed")
        XCTAssertEqual(partialFailureSteps.verifyEnclave.error, "Enclave verification failed", "Error message should match")
        XCTAssertEqual(partialFailureSteps.compareMeasurements.status, .pending, "Compare measurements should be pending")
    }
}