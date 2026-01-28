import XCTest
@testable import TinfoilAI

final class RouterManagerTests: XCTestCase {

    func testATCURLsAreValid() {
        // Test that the ATC URLs are valid
        XCTAssertNotNil(URL(string: TinfoilConstants.atcRoutersURL))
        XCTAssertEqual(TinfoilConstants.atcRoutersURL, "https://atc.tinfoil.sh/routers")

        XCTAssertNotNil(URL(string: TinfoilConstants.atcAttestationURL))
        XCTAssertEqual(TinfoilConstants.atcAttestationURL, "https://atc.tinfoil.sh/attestation")

        XCTAssertEqual(TinfoilConstants.atcBaseURL, "https://atc.tinfoil.sh")
    }

    func testRouterErrorDescriptions() {
        let networkError = RouterManager.RouterError.networkError("Connection failed")
        XCTAssertEqual(networkError.errorDescription, "Failed to fetch routers: Connection failed")

        let invalidResponse = RouterManager.RouterError.invalidResponse
        XCTAssertEqual(invalidResponse.errorDescription, "Invalid response format from router API")

        let noRouters = RouterManager.RouterError.noRoutersFound
        XCTAssertEqual(noRouters.errorDescription, "No routers found in the response")
    }

    func testErrorHandlingDistinction() {
        // This test verifies that the error types are distinct and properly categorized
        // Testing that invalidResponse is different from noRoutersFound
        let invalidResponseError = RouterManager.RouterError.invalidResponse
        let noRoutersError = RouterManager.RouterError.noRoutersFound

        // Ensure they have different descriptions
        XCTAssertNotEqual(invalidResponseError.errorDescription, noRoutersError.errorDescription)

        // Test the error cases are distinct
        switch invalidResponseError {
        case .invalidResponse:
            XCTAssertTrue(true, "Should be invalidResponse")
        default:
            XCTFail("Wrong error type")
        }

        switch noRoutersError {
        case .noRoutersFound:
            XCTAssertTrue(true, "Should be noRoutersFound")
        default:
            XCTFail("Wrong error type")
        }
    }

    func testSelectRouterFromList() throws {
        // Test that selectRouter works with valid input
        let routers = ["router1.example.com", "router2.example.com", "router3.example.com"]

        // Test that selection returns one of the provided routers
        let selected = try RouterManager.selectRouter(from: routers)
        XCTAssertTrue(routers.contains(selected), "Selected router should be from the provided list")
    }

    func testSelectRouterFromEmptyList() {
        // Test that selectRouter throws correct error for empty array
        let emptyRouters: [String] = []

        XCTAssertThrowsError(try RouterManager.selectRouter(from: emptyRouters)) { error in
            guard let routerError = error as? RouterManager.RouterError else {
                XCTFail("Expected RouterError but got \(error)")
                return
            }

            if case .noRoutersFound = routerError {
                // Expected error
            } else {
                XCTFail("Expected noRoutersFound error but got \(routerError)")
            }
        }
    }

    func testSelectRouterRandomness() throws {
        // Test that selection has some randomness (statistical test)
        let routers = ["router1", "router2", "router3"]
        var selections = Set<String>()

        // Run multiple selections to verify randomness
        for _ in 0..<100 {
            let selected = try RouterManager.selectRouter(from: routers)
            selections.insert(selected)
        }

        // With 100 iterations and 3 routers, we expect to see at least 2 different selections
        // The probability of selecting the same router 100 times is (1/3)^100 ≈ 0
        XCTAssertGreaterThanOrEqual(selections.count, 2, "Router selection should show randomness")
    }

    // MARK: - AttestationBundle Tests

    func testAttestationBundleDecoding() throws {
        let json = """
        {
            "domain": "test-enclave.tinfoil.sh",
            "enclaveAttestationReport": {
                "format": "https://tinfoil.sh/predicate/sev-snp-guest/v2",
                "body": "base64-encoded-attestation-body"
            },
            "digest": "sha256:abc123",
            "sigstoreBundle": {"version": "0.1"},
            "vcek": "base64-encoded-vcek-certificate",
            "enclaveCert": "-----BEGIN CERTIFICATE-----\\nMIIC...\\n-----END CERTIFICATE-----"
        }
        """

        let data = json.data(using: .utf8)!
        let bundle = try JSONDecoder().decode(AttestationBundle.self, from: data)

        XCTAssertEqual(bundle.domain, "test-enclave.tinfoil.sh")
        XCTAssertEqual(bundle.enclaveAttestationReport.format, "https://tinfoil.sh/predicate/sev-snp-guest/v2")
        XCTAssertEqual(bundle.enclaveAttestationReport.body, "base64-encoded-attestation-body")
        XCTAssertEqual(bundle.digest, "sha256:abc123")
        XCTAssertEqual(bundle.vcek, "base64-encoded-vcek-certificate")
        XCTAssertTrue(bundle.enclaveCert.contains("BEGIN CERTIFICATE"))
    }

    func testAttestationDocumentDecoding() throws {
        let json = """
        {
            "format": "https://tinfoil.sh/predicate/sev-snp-guest/v2",
            "body": "test-body-content"
        }
        """

        let data = json.data(using: .utf8)!
        let doc = try JSONDecoder().decode(AttestationDocument.self, from: data)

        XCTAssertEqual(doc.format, "https://tinfoil.sh/predicate/sev-snp-guest/v2")
        XCTAssertEqual(doc.body, "test-body-content")
    }

    func testAnyCodableWithVariousTypes() throws {
        let json = """
        {
            "string": "hello",
            "number": 42,
            "float": 3.14,
            "bool": true,
            "null": null,
            "array": [1, 2, 3],
            "object": {"nested": "value"}
        }
        """

        let data = json.data(using: .utf8)!
        let decoded = try JSONDecoder().decode([String: AnyCodable].self, from: data)

        XCTAssertEqual(decoded["string"]?.value as? String, "hello")
        XCTAssertEqual(decoded["number"]?.value as? Int, 42)
        XCTAssertEqual(decoded["bool"]?.value as? Bool, true)
        XCTAssertTrue(decoded["null"]?.value is NSNull)
        XCTAssertNotNil(decoded["array"]?.value as? [Any])
        XCTAssertNotNil(decoded["object"]?.value as? [String: Any])
    }

    func testFetchAttestationBundleIntegration() async throws {
        // Integration test - fetches real attestation bundle from ATC
        let bundle = try await RouterManager.fetchAttestationBundle()

        XCTAssertFalse(bundle.domain.isEmpty, "Domain should not be empty")
        XCTAssertFalse(bundle.enclaveAttestationReport.format.isEmpty, "Format should not be empty")
        XCTAssertFalse(bundle.enclaveAttestationReport.body.isEmpty, "Body should not be empty")
        XCTAssertFalse(bundle.digest.isEmpty, "Digest should not be empty")
        XCTAssertFalse(bundle.vcek.isEmpty, "VCEK should not be empty")
        XCTAssertFalse(bundle.enclaveCert.isEmpty, "Enclave cert should not be empty")
    }
}