import XCTest
@testable import TinfoilAI
import Tinfoil

final class VerificationTests: XCTestCase {

    // MARK: - New Verification Format Tests

    func testNewVerificationFormatFields() async throws {
        // Use SecureClient with default attestation bundle flow
        let secureClient = SecureClient(githubRepo: TinfoilConstants.defaultGithubRepo)

        do {
            let groundTruth = try await secureClient.verify()

            // Verify all new fields are populated
            XCTAssertFalse(groundTruth.tlsPublicKey.isEmpty, "TLS public key should be populated")
            XCTAssertFalse(groundTruth.digest.isEmpty, "Digest should be populated")
            XCTAssertFalse(groundTruth.codeFingerprint.isEmpty, "Code fingerprint should be populated")
            XCTAssertFalse(groundTruth.enclaveFingerprint.isEmpty, "Enclave fingerprint should be populated")

            // Verify HPKE public key exists (may be empty for some configurations)
            XCTAssertNotNil(groundTruth.hpkePublicKey, "HPKE public key field should exist")

            // Verify enclave host is populated from attestation bundle
            XCTAssertNotNil(groundTruth.enclaveHost, "Enclave host should exist")
            XCTAssertFalse(groundTruth.enclaveHost?.isEmpty ?? true, "Enclave host should not be empty")

            // Verify measurements exist
            XCTAssertNotNil(groundTruth.codeMeasurement, "Code measurement should exist")
            XCTAssertNotNil(groundTruth.enclaveMeasurement, "Enclave measurement should exist")

            // Hardware measurement may be nil for non-TDX platforms
            // Just verify the field exists in the structure
            _ = groundTruth.hardwareMeasurement

            // Verify the verification document is properly populated
            let verificationDoc = secureClient.verificationDocument
            XCTAssertNotNil(verificationDoc, "Verification document should be available")
            XCTAssertTrue(verificationDoc?.securityVerified ?? false, "Security should be verified")
            XCTAssertEqual(verificationDoc?.tlsPublicKey, groundTruth.tlsPublicKey, "TLS key should match")
            XCTAssertEqual(verificationDoc?.codeFingerprint, groundTruth.codeFingerprint, "Code fingerprint should match")
            XCTAssertEqual(verificationDoc?.enclaveFingerprint, groundTruth.enclaveFingerprint, "Enclave fingerprint should match")
            XCTAssertFalse(verificationDoc?.selectedRouterEndpoint.isEmpty ?? true, "Router endpoint should be populated")
            XCTAssertEqual(verificationDoc?.schemaVersion, 1)
            XCTAssertEqual(verificationDoc?.verifier.name, TinfoilConstants.verifierName)
            XCTAssertEqual(verificationDoc?.verifier.version, TinfoilConstants.verifierVersion)
            XCTAssertNotNil(verificationDoc?.verifiedAt)
            XCTAssertEqual(verificationDoc?.steps.fetchDigest.status, .skipped)
            XCTAssertEqual(verificationDoc?.steps.verifyCertificate.status, .success)
            XCTAssertTrue(verificationDoc?.allStepsSucceeded ?? false)

            // Verify verifiedEnclaveURL returns the discovered enclave
            let enclaveURL = secureClient.verifiedEnclaveURL
            XCTAssertNotNil(enclaveURL, "Enclave URL should be available after verification")
            XCTAssertTrue(enclaveURL?.starts(with: "https://") ?? false, "Enclave URL should be HTTPS")
        } catch {
            throw XCTSkip("Network verification unavailable: \(error)")
        }
    }

    func testVerificationStepFailures() async throws {
        // Test 1: Invalid attestation URL that should fail early
        let invalidClient = SecureClient(
            githubRepo: TinfoilConstants.defaultGithubRepo,
            attestationBundleURL: "https://invalid-attestation-12345.example.com"
        )

        do {
            _ = try await invalidClient.verify()
            XCTFail("Should have failed with invalid URL")
        } catch {
            let verificationDoc = invalidClient.verificationDocument
            XCTAssertNotNil(verificationDoc, "Should have failure document")
            XCTAssertFalse(verificationDoc?.securityVerified ?? true, "Security should not be verified")
        }

        // Test 2: Invalid GitHub repo that should fail during code verification
        let invalidRepoClient = SecureClient(
            githubRepo: "invalid-org/non-existent-repo"
        )

        do {
            _ = try await invalidRepoClient.verify()
            XCTFail("Should have failed with invalid GitHub repo")
        } catch {
            let verificationDoc = invalidRepoClient.verificationDocument
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
            "enclave_host": "test.tinfoil.sh",
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

        // Verify enclave host is parsed
        XCTAssertEqual(groundTruth.enclaveHost, "test.tinfoil.sh", "Enclave host should match")

        // Test JSON without hardware measurement (non-TDX platform)
        let jsonWithoutHardware = """
        {
            "tls_public_key": "test-tls-key",
            "hpke_public_key": "test-hpke-key",
            "digest": "test-digest",
            "code_fingerprint": "test-code-fp",
            "enclave_fingerprint": "test-enclave-fp",
            "enclave_host": "test.tinfoil.sh",
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
            ("fetchBundle: connection refused", "fetchDigest"),
            ("failed to fetch bundle: connection refused", "fetchDigest"),
            ("verifyCode: invalid repository", "verifyCode"),
            ("verifyEnclave: measurement mismatch", "verifyEnclave"),
            ("verifyHardware: TDX attestation failed", "compareMeasurements"),
            ("validateTLS: certificate invalid", "verifyCertificate"),
            ("verifyCertificate: binding failed", "verifyCertificate"),
            ("measurements: comparison failed", "compareMeasurements"),
            ("unknown error without prefix", "other")
        ]

        for testCase in testCases {
            let steps = SecureClient.stepsFromError(testCase.error)
            let failedStep: String
            if steps.fetchDigest.status == .failed { failedStep = "fetchDigest" }
            else if steps.verifyCode.status == .failed { failedStep = "verifyCode" }
            else if steps.verifyEnclave.status == .failed { failedStep = "verifyEnclave" }
            else if steps.compareMeasurements.status == .failed { failedStep = "compareMeasurements" }
            else if steps.verifyCertificate.status == .failed { failedStep = "verifyCertificate" }
            else { failedStep = "other" }

            XCTAssertEqual(failedStep, testCase.expectedStep)
        }

        let bundleCodeFailure = SecureClient.stepsFromError(
            "verifyCode: invalid signature",
            usesBundle: true
        )
        XCTAssertEqual(bundleCodeFailure.fetchDigest.status, .skipped)
        XCTAssertEqual(bundleCodeFailure.verifyCode.status, .failed)

        let bundleFetchFailure = SecureClient.stepsFromError(
            "fetchBundle: connection refused",
            usesBundle: true
        )
        XCTAssertEqual(bundleFetchFailure.fetchDigest.status, .skipped)
        XCTAssertEqual(bundleFetchFailure.otherError?.status, .failed)

        let pinnedMismatch = SecureClient.stepsFromError(
            "measurements: measurement mismatch",
            pinnedMeasurement: true
        )
        XCTAssertEqual(pinnedMismatch.fetchDigest.status, .skipped)
        XCTAssertEqual(pinnedMismatch.verifyCode.status, .skipped)
        XCTAssertEqual(pinnedMismatch.verifyEnclave.status, .success)
        XCTAssertEqual(pinnedMismatch.compareMeasurements.status, .failed)

        let pinnedEnclaveFailure = SecureClient.stepsFromError(
            "verifyEnclave: bad report",
            pinnedMeasurement: true
        )
        XCTAssertEqual(pinnedEnclaveFailure.fetchDigest.status, .skipped)
        XCTAssertEqual(pinnedEnclaveFailure.verifyCode.status, .skipped)
        XCTAssertEqual(pinnedEnclaveFailure.verifyEnclave.status, .failed)
    }

    // MARK: - Pinned Measurement Tests

    func testPinnedMeasurementVerification() async throws {
        // Learn a live enclave's measurement through the normal Sigstore-backed flow.
        let discovery = SecureClient(githubRepo: TinfoilConstants.defaultGithubRepo)
        let discovered: GroundTruth
        do {
            discovered = try await discovery.verify()
        } catch {
            throw XCTSkip("Network verification unavailable: \(error)")
        }
        guard let enclaveURL = discovery.verifiedEnclaveURL,
              let measurement = discovered.enclaveMeasurement else {
            throw XCTSkip("Discovery did not yield an enclave measurement")
        }

        let pinned = SecureClient(
            enclaveURL: enclaveURL,
            pinnedMeasurement: AttestationMeasurement(type: measurement.type, registers: measurement.registers)
        )
        let groundTruth = try await pinned.verify()

        XCTAssertEqual(groundTruth.configRepo, TinfoilConstants.pinnedNoRepo)
        XCTAssertEqual(groundTruth.digest, "pinned_no_digest")
        XCTAssertNil(groundTruth.releaseTag)
        XCTAssertEqual(groundTruth.enclaveFingerprint, discovered.enclaveFingerprint)
        XCTAssertEqual(groundTruth.codeFingerprint, groundTruth.enclaveFingerprint)
        XCTAssertEqual(groundTruth.hpkePublicKey, discovered.hpkePublicKey)

        let document = pinned.verificationDocument
        XCTAssertEqual(document?.securityVerified, true)
        XCTAssertEqual(document?.steps.fetchDigest.status, .skipped)
        XCTAssertEqual(document?.steps.verifyCode.status, .skipped)
        XCTAssertEqual(document?.steps.verifyEnclave.status, .success)
        XCTAssertEqual(document?.steps.compareMeasurements.status, .success)
        XCTAssertEqual(document?.steps.verifyCertificate.status, .success)
        XCTAssertEqual(document?.allStepsSucceeded, true)

        // Attested requests work against the pinned enclave.
        let response = try await pinned.get(url: "/.well-known/tinfoil-attestation")
        XCTAssertEqual(response.statusCode, 200)

        // A tampered pin is rejected at measurement comparison.
        var tamperedRegisters = measurement.registers
        tamperedRegisters[0] = "00" + tamperedRegisters[0].dropFirst(2)
        let tampered = SecureClient(
            enclaveURL: enclaveURL,
            pinnedMeasurement: AttestationMeasurement(type: measurement.type, registers: tamperedRegisters)
        )
        do {
            _ = try await tampered.verify()
            XCTFail("Tampered pinned measurement should be rejected")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("measurements:"), error.localizedDescription)
            let failure = tampered.verificationDocument
            XCTAssertEqual(failure?.securityVerified, false)
            XCTAssertEqual(failure?.configRepo, TinfoilConstants.pinnedNoRepo)
            XCTAssertEqual(failure?.steps.fetchDigest.status, .skipped)
            XCTAssertEqual(failure?.steps.verifyCode.status, .skipped)
            XCTAssertEqual(failure?.steps.compareMeasurements.status, .failed)
        }
    }

    func testPinnedMeasurementRejectsMalformedMeasurement() async throws {
        let client = SecureClient(
            enclaveURL: "https://enclave.example.com",
            pinnedMeasurement: AttestationMeasurement(type: "", registers: [])
        )
        do {
            _ = try await client.verify()
            XCTFail("Empty pinned measurement should be rejected before any network access")
        } catch {
            XCTAssertTrue(
                error.localizedDescription.contains("at least one register"),
                error.localizedDescription
            )
            XCTAssertEqual(client.verificationDocument?.securityVerified, false)
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
                compareMeasurements: .success(),
                verifyCertificate: .success()
            ),
            releaseTag: "v1.2.3",
            verifier: SoftwareIdentity(name: "tinfoil-go", version: "0.15.0"),
            verifiedAt: "2026-08-04T12:30:00Z"
        )

        // Verify all fields are accessible
        XCTAssertEqual(testDoc.configRepo, "test-repo")
        XCTAssertEqual(testDoc.enclaveHost, "test-url")
        XCTAssertEqual(testDoc.releaseDigest, "test-digest")
        XCTAssertEqual(testDoc.schemaVersion, 1)
        XCTAssertEqual(testDoc.releaseTag, "v1.2.3")
        XCTAssertEqual(testDoc.verifier.name, "tinfoil-go")
        XCTAssertEqual(testDoc.verifier.version, "0.15.0")
        XCTAssertEqual(testDoc.verifiedAt, "2026-08-04T12:30:00Z")
        XCTAssertEqual(testDoc.tlsPublicKey, "test-tls")
        XCTAssertEqual(testDoc.hpkePublicKey, "test-hpke")
        XCTAssertEqual(testDoc.codeFingerprint, "code-fp")
        XCTAssertEqual(testDoc.enclaveFingerprint, "enclave-fp")
        XCTAssertEqual(testDoc.selectedRouterEndpoint, "router.example.com")
        XCTAssertTrue(testDoc.securityVerified)
        XCTAssertNotNil(testDoc.hardwareMeasurement)
        XCTAssertEqual(testDoc.hardwareMeasurement?.id, "TDX-1")
    }

    func testLegacyVerificationDocumentDecoding() throws {
        let json = """
        {
          "configRepo":"owner/repo",
          "enclaveHost":"router.example",
          "releaseDigest":"digest",
          "codeMeasurement":{"type":"type","registers":["code"]},
          "enclaveMeasurement":{"measurement":{"type":"type","registers":["enclave"]}},
          "tlsPublicKey":"tls",
          "hpkePublicKey":"hpke",
          "hardwareMeasurement":{"id":"id","mrtd":"mrtd","rtmr0":"rtmr0"},
          "codeFingerprint":"code-fingerprint",
          "enclaveFingerprint":"enclave-fingerprint",
          "selectedRouterEndpoint":"router.example",
          "securityVerified":true,
          "steps":{
            "fetchDigest":{"status":"success"},
            "verifyCode":{"status":"success"},
            "verifyEnclave":{"status":"success"},
            "compareMeasurements":{"status":"success"}
          }
        }
        """

        let document = try JSONDecoder().decode(
            VerificationDocument.self,
            from: Data(json.utf8)
        )

        XCTAssertEqual(document.schemaVersion, 0)
        XCTAssertEqual(document.verifier.name, "unknown")
        XCTAssertEqual(document.steps.verifyCertificate.status, .pending)
        XCTAssertEqual(document.hardwareMeasurement?.id, "id")
    }

    func testCanonicalVerificationDocumentDecoding() throws {
        let json = """
        {
          "schemaVersion":1,
          "configRepo":"owner/repo",
          "enclaveHost":"router.example",
          "releaseTag":"v1.2.3",
          "releaseDigest":"digest",
          "codeMeasurement":{"type":"type","registers":["code"]},
          "enclaveMeasurement":{"measurement":{"type":"type","registers":["enclave"]}},
          "tlsPublicKey":"tls",
          "hpkePublicKey":"hpke",
          "hardwareMeasurement":{"ID":"id","MRTD":"mrtd","RTMR0":"rtmr0"},
          "codeFingerprint":"code-fingerprint",
          "enclaveFingerprint":"enclave-fingerprint",
          "selectedRouterEndpoint":"router.example",
          "securityVerified":true,
          "verifier":{"name":"tinfoil-go","version":"0.15.0"},
          "verifiedAt":"2026-08-04T12:30:00Z",
          "steps":{
            "fetchDigest":{"status":"success"},
            "verifyCode":{"status":"success"},
            "verifyEnclave":{"status":"success"},
            "compareMeasurements":{"status":"success"},
            "verifyCertificate":{"status":"success"}
          }
        }
        """

        let document = try JSONDecoder().decode(
            VerificationDocument.self,
            from: Data(json.utf8)
        )

        XCTAssertTrue(document.allStepsSucceeded)
        XCTAssertEqual(document.verifier.version, "0.15.0")
        XCTAssertEqual(document.hardwareMeasurement?.id, "id")

        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        var steps = try XCTUnwrap(object["steps"] as? [String: Any])
        steps.removeValue(forKey: "verifyCertificate")
        object["steps"] = steps
        let missingCertificateStep = try JSONSerialization.data(withJSONObject: object)
        XCTAssertThrowsError(
            try JSONDecoder().decode(VerificationDocument.self, from: missingCertificateStep)
        )
    }

    func testCanonicalDocumentRequiresVerifierIdentity() {
        let json = """
        {
          "schemaVersion":1,
          "configRepo":"owner/repo",
          "enclaveHost":"router.example",
          "releaseDigest":"digest",
          "codeMeasurement":{"type":"type","registers":["code"]},
          "enclaveMeasurement":{"measurement":{"type":"type","registers":["enclave"]}},
          "tlsPublicKey":"tls",
          "hpkePublicKey":"hpke",
          "codeFingerprint":"code-fingerprint",
          "enclaveFingerprint":"enclave-fingerprint",
          "selectedRouterEndpoint":"router.example",
          "securityVerified":true,
          "verifiedAt":"2026-08-04T12:30:00Z",
          "steps":{
            "fetchDigest":{"status":"success"},
            "verifyCode":{"status":"success"},
            "verifyEnclave":{"status":"success"},
            "compareMeasurements":{"status":"success"},
            "verifyCertificate":{"status":"success"}
          }
        }
        """

        XCTAssertThrowsError(
            try JSONDecoder().decode(VerificationDocument.self, from: Data(json.utf8))
        )
    }

    // MARK: - SecureClient HTTP Methods

    func testGetBeforeVerifyThrowsNotVerified() async {
        let client = SecureClient(githubRepo: TinfoilConstants.defaultGithubRepo)

        do {
            _ = try await client.get(url: "/health")
            XCTFail("Should throw when calling get() before verify()")
        } catch let error as VerificationError {
            if case .notVerified = error {
                // Expected
            } else {
                XCTFail("Expected VerificationError.notVerified, got \(error)")
            }
        } catch {
            XCTFail("Expected VerificationError, got \(error)")
        }
    }

    func testPostBeforeVerifyThrowsNotVerified() async {
        let client = SecureClient(githubRepo: TinfoilConstants.defaultGithubRepo)

        do {
            _ = try await client.post(url: "/api/test", body: Data())
            XCTFail("Should throw when calling post() before verify()")
        } catch let error as VerificationError {
            if case .notVerified = error {
                // Expected
            } else {
                XCTFail("Expected VerificationError.notVerified, got \(error)")
            }
        } catch {
            XCTFail("Expected VerificationError, got \(error)")
        }
    }

    func testSecureGetAfterVerify() async throws {
        let client = SecureClient(githubRepo: TinfoilConstants.defaultGithubRepo)

        do {
            _ = try await client.verify()
        } catch {
            throw XCTSkip("Verification failed (network issue): \(error)")
        }

        let response = try await client.get(url: "/v1/models")
        XCTAssertTrue([200, 401].contains(response.statusCode),
                      "Models endpoint should return 200 or 401 (no API key)")
        XCTAssertNotNil(response.bodyString)
    }

    func testSecureGetWithHeaders() async throws {
        let client = SecureClient(githubRepo: TinfoilConstants.defaultGithubRepo)

        do {
            _ = try await client.verify()
        } catch {
            throw XCTSkip("Verification failed (network issue): \(error)")
        }

        let apiKey = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] ?? ""
        let response = try await client.get(
            url: "/v1/models",
            headers: [
                "Accept": "application/json",
                "Authorization": "Bearer \(apiKey)"
            ]
        )
        XCTAssertTrue([200, 401].contains(response.statusCode))
    }

    func testSecurePostWithBody() async throws {
        let client = SecureClient(githubRepo: TinfoilConstants.defaultGithubRepo)

        do {
            _ = try await client.verify()
        } catch {
            throw XCTSkip("Verification failed (network issue): \(error)")
        }

        let body = try JSONSerialization.data(withJSONObject: [
            "model": "gpt-oss-120b",
            "messages": [["role": "user", "content": "Say hi"]],
            "max_tokens": 5
        ])

        let response = try await client.post(
            url: "/v1/chat/completions",
            headers: [
                "Content-Type": "application/json",
                "Authorization": "Bearer \(ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] ?? "")"
            ],
            body: body
        )

        XCTAssertTrue([200, 401].contains(response.statusCode),
                      "Should get 200 (success) or 401 (no API key in CI)")
        XCTAssertNotNil(response.bodyString, "Response should have a body")
    }

    func testSecureResponseBodyString() {
        let data = "hello world".data(using: .utf8)!
        let response = SecureResponse(statusCode: 200, body: data)

        XCTAssertEqual(response.bodyString, "hello world")
        XCTAssertEqual(response.statusCode, 200)
    }

    func testSecureGetWithNilAndEmptyHeaders() async throws {
        let client = SecureClient(githubRepo: TinfoilConstants.defaultGithubRepo)

        do {
            _ = try await client.verify()
        } catch {
            throw XCTSkip("Verification failed (network issue): \(error)")
        }

        // Verify nil and empty headers don't crash
        let response = try await client.get(url: "/v1/models", headers: nil)
        XCTAssertTrue([200, 401].contains(response.statusCode))

        let response2 = try await client.get(url: "/v1/models", headers: [:])
        XCTAssertEqual(response.statusCode, response2.statusCode)
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
