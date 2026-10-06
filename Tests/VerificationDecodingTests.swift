import XCTest
import Foundation
@testable import TinfoilAI

/// Pins the Swift side of the verifier payload contract. The Go side is
/// verificationJSON in tinfoil-go's mobile/verification.go.
final class VerificationDecodingTests: XCTestCase {
    private static let host = "router.inference.tinfoil.sh"

    private func payload(_ changes: [String: Any?] = [:]) throws -> String {
        var fields: [String: Any] = [
            "schema_version": 1,
            "config_repo": "tinfoilsh/confidential-model-router",
            "code_digest": "abc123",
            "code_tag": "v1.2.3",
            "code_measurement": ["type": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1", "registers": ["aa", "bb", "cc"]],
            "enclave_measurement": ["type": "https://tinfoil.sh/predicate/tdx-guest/v2", "registers": ["dd", "ee"]],
            "tls_public_key_fp": "deadbeef",
            "hpke_public_key": "cafebabe",
            "crypto_material": [
                ["id": "tls", "format": "https://tinfoil.sh/key/spki-fp-sha256/v1", "data": "deadbeef"],
                ["id": "hpke", "format": "https://tinfoil.sh/key/x25519-hpke/v1", "data": "cafebabe"],
            ],
            "freshness_expires_at": "2026-10-03T12:00:00.5Z",
            "verified_at": "2026-09-26T12:00:00Z",
        ]
        for (key, value) in changes {
            fields[key] = value
        }
        let data = try JSONSerialization.data(withJSONObject: fields)
        return String(decoding: data, as: UTF8.self)
    }

    private func assertAttestationError(
        _ expression: @autoclosure () throws -> Verification,
        containing expected: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            guard case TinfoilError.attestationError(let message) = error else {
                return XCTFail("expected an attestation error, got \(error)", file: file, line: line)
            }
            XCTAssertTrue(message.contains(expected), "\(message) should mention \(expected)", file: file, line: line)
        }
    }

    func testDecodesPayload() throws {
        let verification = try Verification(payload: payload(), enclaveHost: Self.host)

        XCTAssertEqual(verification.enclaveHost, Self.host)
        XCTAssertEqual(verification.configRepo, "tinfoilsh/confidential-model-router")
        XCTAssertEqual(verification.codeDigest, "abc123")
        XCTAssertEqual(verification.codeTag, "v1.2.3")
        XCTAssertEqual(verification.codeMeasurement?.registers, ["aa", "bb", "cc"])
        XCTAssertEqual(verification.enclaveMeasurement?.type, "https://tinfoil.sh/predicate/tdx-guest/v2")
        XCTAssertEqual(verification.tlsPublicKeyFingerprint, "deadbeef")
        XCTAssertEqual(verification.hpkePublicKey, "cafebabe")
        XCTAssertEqual(verification.cryptoMaterial.map(\.id), ["tls", "hpke"])
        XCTAssertEqual(verification.freshnessExpiresAt, Date(timeIntervalSince1970: 1_791_028_800.5))
        XCTAssertEqual(verification.verifiedAt, Date(timeIntervalSince1970: 1_790_424_000))
        XCTAssertEqual(
            verification.verifier,
            SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion),
            "The payload names no verifier; the SDK records itself."
        )
    }

    func testOmittedOptionalFieldsDecodeAsNil() throws {
        let verification = try Verification(
            payload: payload([
                "code_tag": nil,
                "code_measurement": nil,
                "enclave_measurement": nil,
                "hpke_public_key": nil,
            ]),
            enclaveHost: Self.host
        )
        XCTAssertNil(verification.codeTag)
        XCTAssertNil(verification.codeMeasurement)
        XCTAssertNil(verification.enclaveMeasurement)
        XCTAssertNil(verification.hpkePublicKey, "An enclave that endorses only TLS has no HPKE key.")
    }

    func testIgnoresFieldsTheSDKRecordsItself() throws {
        let verification = try Verification(
            payload: payload([
                "enclave_host": "elsewhere.example",
                "verifier": ["name": "tinfoil-go", "version": "devel"],
            ]),
            enclaveHost: Self.host
        )
        XCTAssertEqual(verification.enclaveHost, Self.host)
        XCTAssertEqual(verification.verifier.name, TinfoilConstants.sdkName)
    }

    func testDatesWithAndWithoutFractionalSeconds() throws {
        for (value, seconds) in [
            ("2026-10-03T12:00:00Z", 1_791_028_800.0),
            ("2026-10-03T12:00:00.5Z", 1_791_028_800.5),
            ("2026-10-03T12:00:00.123456789Z", 1_791_028_800.123),
        ] {
            let verification = try Verification(payload: payload(["freshness_expires_at": value]), enclaveHost: Self.host)
            XCTAssertEqual(verification.freshnessExpiresAt.timeIntervalSince1970, seconds, accuracy: 0.001, value)
        }
    }

    func testRejectsAnotherSchemaVersion() {
        assertAttestationError(
            try Verification(payload: #"{"schema_version":2}"#, enclaveHost: Self.host),
            containing: "unsupported verification schema version 2"
        )
    }

    func testRejectsMissingField() throws {
        assertAttestationError(
            try Verification(payload: payload(["code_digest": nil]), enclaveHost: Self.host),
            containing: "unreadable verification payload"
        )
    }

    func testRejectsInvalidDate() throws {
        assertAttestationError(
            try Verification(payload: payload(["freshness_expires_at": "next week"]), enclaveHost: Self.host),
            containing: "freshness_expires_at"
        )
    }

    func testClassifiesVerifierErrorsByPrefix() {
        func classify(_ message: String) -> TinfoilError {
            TinfoilError.fromVerifier(
                NSError(domain: "go", code: 1, userInfo: [NSLocalizedDescriptionKey: message]),
                configurationPrefix: "configuration error: ",
                attestationPrefix: "attestation error: "
            )
        }
        XCTAssertEqual(classify("configuration error: bad repo"), .invalidConfiguration("bad repo"))
        XCTAssertEqual(classify("attestation error: quote rejected"), .attestationError("quote rejected"))
        XCTAssertEqual(
            classify("unexpected"),
            .attestationError("unexpected"),
            "An uncategorized verifier failure still fails closed."
        )
    }
}
