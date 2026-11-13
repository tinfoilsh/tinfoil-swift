import XCTest
import Foundation
@testable import Tinfoil

/// Pins the Swift side of the verifier payload contract. The other side is
/// verificationJSON in the TinfoilGo framework's mobile/verification.go.
final class VerificationDecodingTests: XCTestCase {
    private static let host = "router.inference.tinfoil.sh"

    private func payload(_ changes: [String: Any?] = [:]) throws -> String {
        var fields: [String: Any] = [
            "schema_version": 1,
            "config_repo": "tinfoilsh/confidential-model-router",
            "code_digest": "abc123",
            "code_tag": "v1.2.3",
            "code_measurement": ["type": "https://tinfoil.sh/predicate/tdx-guest/v2", "registers": ["", "", "bb", "cc", ""]],
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
            guard case TinfoilError.attestationError(let failure) = error else {
                return XCTFail("expected an attestation error, got \(error)", file: file, line: line)
            }
            XCTAssertTrue(failure.message.contains(expected), "\(failure.message) should mention \(expected)", file: file, line: line)
        }
    }

    func testDecodesPayload() throws {
        let verification = try Verification(payload: payload())

        XCTAssertEqual(verification.configRepo, "tinfoilsh/confidential-model-router")
        XCTAssertEqual(verification.codeDigest, "abc123")
        XCTAssertEqual(verification.codeTag, "v1.2.3")
        XCTAssertEqual(verification.codeMeasurement?.registers, ["", "", "bb", "cc", ""])
        XCTAssertEqual(verification.enclaveMeasurement?.type, "https://tinfoil.sh/predicate/tdx-guest/v2")
        XCTAssertEqual(verification.tlsPublicKeyFingerprint, "deadbeef")
        XCTAssertEqual(verification.hpkePublicKey, "cafebabe")
        XCTAssertEqual(verification.cryptoMaterial.map(\.id), ["tls", "hpke"])
        XCTAssertEqual(verification.freshnessExpiresAt, Date(timeIntervalSince1970: 1_791_028_800.5))
        XCTAssertEqual(verification.metadata.verifiedAt, Date(timeIntervalSince1970: 1_790_424_000))
        XCTAssertEqual(
            verification.metadata.verifier,
            SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion),
            "The payload names no verifier; the SDK records itself."
        )
    }

    func testOmittedFieldsDecodeAsEmptyOrNil() throws {
        let verification = try Verification(
            payload: payload([
                "code_tag": nil,
                "code_measurement": nil,
                "enclave_measurement": nil,
                "hpke_public_key": nil,
            ])
        )
        XCTAssertEqual(verification.codeTag, "")
        XCTAssertNil(verification.codeMeasurement)
        XCTAssertNil(verification.enclaveMeasurement)
        XCTAssertEqual(verification.hpkePublicKey, "", "An enclave that endorses only TLS has no HPKE key.")
        XCTAssertNil(verification.config, "A code-release verification has no config.")
        XCTAssertNil(verification.runtime)
        XCTAssertNil(verification.platform)
    }

    func testDecodesConfigFacts() throws {
        let verification = try Verification(
            payload: payload([
                "config": [
                    "source": "endorsement", "name": "/org/project/v1", "digest": "c0",
                    "reference": "sha256:c0", "signing_key_hint": "hint",
                    "approval_time": "2026-09-20T08:00:00Z", "registry_id": "registry",
                    "signature_time": "2026-09-20T08:01:00.5Z",
                ],
                "runtime": [
                    "source": "endorsement", "repo": "tinfoilsh/cvmimage", "tag": "v0.15.0",
                    "digest": "r0", "name": "runtime", "commit": "abc",
                    "approval_time": "2026-09-20T08:00:00Z",
                ],
                "platform": ["source": "embedded", "digest": "p0"],
            ])
        )
        let approved = Date(timeIntervalSince1970: 1_789_891_200)
        XCTAssertEqual(verification.config, ConfigVerification(
            source: .endorsement, name: "/org/project/v1", digest: "c0", reference: "sha256:c0",
            signingKeyHint: "hint", approvalTime: approved, registryID: "registry",
            signatureTime: approved.addingTimeInterval(60.5)
        ))
        XCTAssertEqual(verification.runtime, ArtifactVerification(
            source: .endorsement, repo: "tinfoilsh/cvmimage", tag: "v0.15.0", digest: "r0",
            name: "runtime", commit: "abc", approvalTime: approved
        ))
        XCTAssertEqual(
            verification.platform,
            ArtifactVerification(source: .embedded, repo: "", tag: "", digest: "p0", name: "", commit: "", approvalTime: nil),
            "Absent facts are empty strings and nil times."
        )
    }

    func testAPolicyApprovedConfigHasOnlyItsDigest() throws {
        let verification = try Verification(payload: payload(["config": ["source": "policy", "digest": "c0"]]))
        XCTAssertEqual(
            verification.config,
            ConfigVerification(
                source: .policy, name: "", digest: "c0", reference: "",
                signingKeyHint: "", approvalTime: nil, registryID: "", signatureTime: nil
            ),
            "No endorsement-only fact is reported for a policy approval."
        )
    }

    func testRejectsAConfigFactWithAnInvalidTime() throws {
        assertAttestationError(
            try Verification(payload: payload(["config": ["source": "endorsement", "digest": "c0", "approval_time": "yesterday"]])),
            containing: "config.approval_time"
        )
    }

    func testIgnoresFieldsTheSDKRecordsItself() throws {
        let verification = try Verification(
            payload: payload([
                "verifier": ["name": "tinfoil-go", "version": "devel"],
            ])
        )
        XCTAssertEqual(verification.metadata.verifier.name, TinfoilConstants.sdkName)
    }

    func testDatesWithAndWithoutFractionalSeconds() throws {
        for (value, seconds) in [
            ("2026-10-03T12:00:00Z", 1_791_028_800.0),
            ("2026-10-03T12:00:00.5Z", 1_791_028_800.5),
            ("2026-10-03T12:00:00.123456789Z", 1_791_028_800.123),
        ] {
            let verification = try Verification(payload: payload(["freshness_expires_at": value]))
            XCTAssertEqual(verification.freshnessExpiresAt.timeIntervalSince1970, seconds, accuracy: 0.001, value)
        }
    }

    func testRejectsAnotherSchemaVersion() {
        assertAttestationError(
            try Verification(payload: #"{"schema_version":2}"#),
            containing: "unsupported verification schema version 2"
        )
    }

    func testRejectsMissingField() throws {
        assertAttestationError(
            try Verification(payload: payload(["code_digest": nil])),
            containing: "unreadable verification payload"
        )
    }

    func testRejectsInvalidDate() throws {
        assertAttestationError(
            try Verification(payload: payload(["freshness_expires_at": "next week"])),
            containing: "freshness_expires_at"
        )
    }

    func testClassifiesVerifierErrorsByPrefix() {
        func classify(_ message: String) -> TinfoilError {
            TinfoilError.fromVerifier(
                NSError(domain: "go", code: 1, userInfo: [NSLocalizedDescriptionKey: message]),
                usagePrefix: "usage error: ",
                verificationPrefix: "verification error: "
            )
        }
        XCTAssertEqual(classify("usage error: bad repo"), .configuration("bad repo"))
        XCTAssertEqual(classify("verification error: quote: rejected"), .attestation("quote: rejected", layer: .quote))
        XCTAssertEqual(
            classify("verification error: firmware: rejected"),
            .attestation("firmware: rejected", layer: VerificationLayer(rawValue: "firmware")),
            "A layer this SDK doesn't name is still carried."
        )
        XCTAssertEqual(classify("verification error: rejected"), .attestation("rejected"), "No layer, no guess.")
        XCTAssertEqual(
            classify("verification error: could not parse: bad JSON"),
            .attestation("could not parse: bad JSON"),
            "Text before a colon is a layer only if it is a single lowercase word."
        )
        XCTAssertEqual(
            classify("unexpected"),
            .attestation("unexpected"),
            "An uncategorized verifier failure still fails closed."
        )
    }
}
