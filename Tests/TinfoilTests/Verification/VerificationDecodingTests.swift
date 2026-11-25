import XCTest
import Foundation
@testable import Tinfoil

/// Pins the Swift side of the verifier result contract, bridge schema 3: the
/// report's JSON form in a wrapper. The other side is resultJSON in the
/// TinfoilGo framework's mobile/verification.go.
final class VerificationDecodingTests: XCTestCase {
    private static let host = "router.inference.tinfoil.sh"

    private static let passedSteps: [[String: Any]] = ["envelope", "provenance", "quote", "policy"].map {
        ["layer": $0, "status": "passed"]
    }

    /// The result of an accepted document, with changes to its verified facts
    private func payload(_ changes: [String: Any?] = [:]) throws -> String {
        var facts: [String: Any] = [
            "config_repo": "tinfoilsh/confidential-model-router",
            "code_digest": "abc123",
            "code_tag": "v1.2.3",
            "code_measurement": ["platform": "tdx", "rtmr1": "bb", "rtmr2": "cc"],
            "enclave_measurement": ["platform": "tdx", "mrtd": "dd", "rtmr0": "ee", "rtmr1": "bb", "rtmr2": "cc", "rtmr3": "ff"],
            "crypto_material": [
                ["id": "tls", "format": "https://tinfoil.sh/key/spki-fp-sha256/v1", "data": "deadbeef"],
                ["id": "hpke", "format": "https://tinfoil.sh/key/x25519-hpke/v1", "data": "cafebabe"],
            ],
            "freshness_expires_at": "2026-10-03T12:00:00.5Z",
        ]
        for (key, value) in changes {
            facts[key] = value
        }
        return try json([
            "schema_version": 3,
            "report": [
                "schema_version": 1,
                "steps": Self.passedSteps,
                "verified_facts": facts,
                "metadata": ["verified_at": "2026-09-26T12:00:00Z"],
            ] as [String: Any],
        ])
    }

    /// The result of a document that the verifier rejected at the quote layer
    private func rejection(
        partialFacts: [String: Any] = [:],
        failing layer: String = "quote",
        message: String = "verification error: quote: signature does not verify"
    ) throws -> String {
        let layers = ["envelope", "provenance", "quote", "policy"]
        let failed = layers.firstIndex(of: layer) ?? layers.count
        let result: [String: Any] = [
            "schema_version": 3,
            "report": [
                "schema_version": 1,
                "steps": layers.enumerated().map { index, step -> [String: Any] in
                    index < failed ? ["layer": step, "status": "passed"]
                        : index == failed ? ["layer": step, "status": "failed", "message": message]
                        : ["layer": step, "status": "not_run"]
                },
                "partial_facts": partialFacts,
                "metadata": ["verified_at": "2026-09-26T12:00:00Z"],
            ] as [String: Any],
            "error": ["layer": layer, "message": message],
        ]
        return try json(result)
    }

    private func json(_ object: [String: Any]) throws -> String {
        String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    private func decode(_ payload: String) throws -> VerificationReport {
        try VerificationReport.decodeResult(payload, verificationPrefix: "verification error: ")
    }

    /// The verified facts of an accepted result
    private func facts(_ payload: String) throws -> VerifiedFacts {
        try XCTUnwrap(decode(payload).verifiedFacts)
    }

    private func assertAttestationError(
        _ expression: @autoclosure () throws -> Any,
        containing expected: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            guard case TinfoilError.attestationError(let failure) = error else {
                return XCTFail("expected an attestation error, got \(error)", file: file, line: line)
            }
            XCTAssertTrue(failure.message.contains(expected), "\(failure.message) should mention \(expected)", file: file, line: line)
            XCTAssertNil(failure.verificationError, "A result that can't be read carries no report.", file: file, line: line)
        }
    }

    func testDecodesAnAcceptedResult() throws {
        let report = try decode(payload())
        let verification = try XCTUnwrap(report.verifiedFacts)

        XCTAssertEqual(verification.configRepo, "tinfoilsh/confidential-model-router")
        XCTAssertEqual(verification.codeDigest, "abc123")
        XCTAssertEqual(verification.codeTag, "v1.2.3")
        XCTAssertEqual(verification.codeMeasurement?.registers, ["", "", "bb", "cc", ""])
        XCTAssertEqual(verification.enclaveMeasurement, VerifiedFacts.Measurement(
            type: "https://tinfoil.sh/predicate/tdx-guest/v2",
            registers: ["dd", "ee", "bb", "cc", "ff"]
        ))
        XCTAssertEqual(verification.tlsPublicKeyFingerprint, "deadbeef", "The TLS key is lifted from crypto_material.")
        XCTAssertEqual(verification.hpkePublicKey, "cafebabe", "The HPKE key is lifted from crypto_material.")
        XCTAssertEqual(verification.cryptoMaterial.map(\.id), ["tls", "hpke"])
        XCTAssertEqual(verification.freshnessExpiresAt, Date(timeIntervalSince1970: 1_791_028_800.5))
        XCTAssertEqual(report.steps.map(\.layer), [.envelope, .provenance, .quote, .policy])
        XCTAssertTrue(report.steps.allSatisfy { $0.status == .passed && $0.message.isEmpty })
        XCTAssertNil(report.partialFacts, "An accepted document has no partial facts.")
        XCTAssertEqual(report.metadata.verifiedAt, Date(timeIntervalSince1970: 1_790_424_000))
        XCTAssertEqual(
            report.metadata.verifier,
            SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion),
            "The payload names no verifier; the SDK records itself."
        )
    }

    func testOmittedFieldsDecodeAsEmptyOrNil() throws {
        let verification = try facts(
            payload([
                "code_tag": nil,
                "code_measurement": nil,
                "enclave_measurement": nil,
                "crypto_material": [
                    ["id": "tls", "format": "https://tinfoil.sh/key/spki-fp-sha256/v1", "data": "deadbeef"],
                ],
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
        let verification = try facts(
            payload([
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
        let verification = try facts(payload(["config": ["source": "policy", "digest": "c0"]]))
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
            try decode(payload(["config": ["source": "endorsement", "digest": "c0", "approval_time": "yesterday"]])),
            containing: "config.approval_time"
        )
        assertAttestationError(
            try decode(payload(["runtime": ["source": "endorsement", "digest": "r0", "approval_time": "yesterday"]])),
            containing: "runtime.approval_time"
        )
    }

    func testIgnoresFieldsTheSDKRecordsItself() throws {
        let report = try decode(payload([
            "verifier": ["name": "tinfoil-go", "version": "devel"],
        ]))
        XCTAssertEqual(report.metadata.verifier.name, TinfoilConstants.sdkName)
    }

    func testDatesWithAndWithoutFractionalSeconds() throws {
        for (value, seconds) in [
            ("2026-10-03T12:00:00Z", 1_791_028_800.0),
            ("2026-10-03T12:00:00.5Z", 1_791_028_800.5),
            ("2026-10-03T12:00:00.123456789Z", 1_791_028_800.123),
        ] {
            let verification = try facts(payload(["freshness_expires_at": value]))
            XCTAssertEqual(verification.freshnessExpiresAt.timeIntervalSince1970, seconds, accuracy: 0.001, value)
        }
    }

    func testFindsTheChannelKeysByIDAndFormat() throws {
        let verification = try facts(payload([
            "crypto_material": [
                ["id": "tls", "format": "https://tinfoil.sh/key/other/v1", "data": "00"],
                ["id": "hpke", "format": "https://tinfoil.sh/key/spki-fp-sha256/v1", "data": "11"],
                ["id": "extra", "format": "https://tinfoil.sh/key/x25519-hpke/v1", "data": "22"],
            ],
        ]))
        XCTAssertEqual(verification.tlsPublicKeyFingerprint, "", "A tls item in another format is not the TLS key.")
        XCTAssertEqual(verification.hpkePublicKey, "", "Only the hpke item in the HPKE format is the HPKE key.")
        XCTAssertEqual(verification.cryptoMaterial.map(\.data), ["00", "11", "22"], "Every item is kept, in order.")
    }

    func testRejectsAMeasurementOfAnUnknownPlatform() throws {
        assertAttestationError(
            try decode(payload(["enclave_measurement": ["platform": "cca", "rim": "aa"]])),
            containing: "unknown verified_facts.enclave_measurement platform: cca"
        )
    }

    func testIgnoresMeasurementMembersThatItDoesNotKnow() throws {
        let verification = try facts(payload(["code_measurement": ["platform": "sev-snp", "launch": "aa", "rtmr1": "bb", "note": 1]]))
        XCTAssertEqual(
            verification.codeMeasurement,
            VerifiedFacts.Measurement(type: "https://tinfoil.sh/predicate/sev-snp-guest/v2", registers: ["aa"])
        )
    }

    func testRejectsANullRegister() throws {
        assertAttestationError(
            try decode(payload(["code_measurement": ["platform": "tdx", "rtmr1": NSNull(), "rtmr2": "cc"]])),
            containing: "unreadable verification result"
        )
    }

    func testRejectsAnotherReportSchemaVersion() throws {
        var result = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(payload().utf8)) as? [String: Any])
        var report = try XCTUnwrap(result["report"] as? [String: Any])
        report["schema_version"] = 2
        result["report"] = report
        assertAttestationError(try decode(json(result)), containing: "unsupported verification report schema version 2")
        report["schema_version"] = nil
        result["report"] = report
        assertAttestationError(try decode(json(result)), containing: "unsupported verification report schema version none")
    }

    func testRejectsAnotherSchemaVersion() throws {
        for version in [1, 2, 4] {
            assertAttestationError(
                try decode(#"{"schema_version":\#(version)}"#),
                containing: "unsupported verification schema version \(version)"
            )
        }
        // A version 2 payload had the same wrapper around another report.
        var legacy = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(payload().utf8)) as? [String: Any])
        legacy["schema_version"] = 2
        assertAttestationError(try decode(json(legacy)), containing: "unsupported verification schema version 2")
    }

    func testRejectsMissingField() throws {
        assertAttestationError(
            try decode(payload(["code_digest": nil])),
            containing: "unreadable verification result"
        )
    }

    func testRejectsInvalidDate() throws {
        assertAttestationError(
            try decode(payload(["freshness_expires_at": "next week"])),
            containing: "freshness_expires_at"
        )
    }

    func testARejectedResultThrowsTheVerifierErrorWithItsReport() throws {
        let partial: [String: Any] = [
            "expected": [
                "config_repo": "tinfoilsh/confidential-model-router",
                "artifact": ["source": "endorsement", "repo": "tinfoilsh/confidential-model-router", "tag": "v1.2.3", "digest": "abc123"],
                "code_measurement": ["platform": "tdx", "rtmr1": "bb", "rtmr2": "cc"],
            ],
            "measured": ["tls_public_key_fp": "deadbeef", "hpke_public_key_fp": "f00d"],
        ]
        XCTAssertThrowsError(try decode(rejection(partialFacts: partial))) { error in
            guard case TinfoilError.attestationError(let failure) = error else {
                return XCTFail("expected an attestation error, got \(error)")
            }
            XCTAssertEqual(failure.message, "quote: signature does not verify", "The bridge's prefix is dropped.")
            guard let rejected = failure.verificationError else {
                return XCTFail("the verifier's error must be the cause")
            }
            XCTAssertEqual(rejected.layer, .quote)
            XCTAssertEqual(rejected.message, "quote: signature does not verify")
            XCTAssertEqual(rejected.description, "verification error: quote: signature does not verify")
            let report = rejected.report
            XCTAssertEqual(report.steps.map(\.status), [.passed, .passed, .failed, .notRun])
            XCTAssertEqual(report.steps[2].message, "verification error: quote: signature does not verify")
            XCTAssertNil(report.verifiedFacts, "A failed report has no verified facts.")
            let expected = try? XCTUnwrap(report.partialFacts?.expected)
            XCTAssertEqual(expected?.configRepo, "tinfoilsh/confidential-model-router")
            XCTAssertEqual(expected?.artifact.tag, "v1.2.3")
            XCTAssertEqual(expected?.artifact.name, "", "Absent artifact facts are empty.")
            XCTAssertEqual(expected?.codeMeasurement?.registers, ["", "", "bb", "cc", ""])
            XCTAssertNil(expected?.measurement, "The policy step never resolved the full registers.")
            XCTAssertNil(expected?.config)
            XCTAssertEqual(
                report.partialFacts?.measured,
                MeasuredFacts(cpu: nil, tlsPublicKeyFingerprint: "deadbeef", hpkePublicKeyFingerprint: "f00d"),
                "A report holds fingerprints, and no CPU measurement before the quote passed."
            )
        }
    }

    func testDecodesAPolicyFailureSideBySide() throws {
        let partial: [String: Any] = [
            "expected": [
                "config_repo": "org/repo",
                "artifact": ["source": "endorsement", "digest": "abc123"],
                "measurement": ["platform": "tdx", "mrtd": "aa", "rtmr0": "bb", "rtmr1": "cc", "rtmr2": "dd", "rtmr3": "ee"],
            ],
            "measured": ["cpu_measurement": ["platform": "tdx", "mrtd": "aa", "rtmr0": "bb", "rtmr1": "cc", "rtmr2": "dd", "rtmr3": "ff"]],
        ]
        let result = try rejection(partialFacts: partial, failing: "policy", message: "verification error: policy: RTMR3 mismatch")
        XCTAssertThrowsError(try decode(result)) { error in
            guard let report = (error as? TinfoilError)?.verificationError?.report else {
                return XCTFail("expected a report, got \(error)")
            }
            XCTAssertEqual(report.partialFacts?.expected?.measurement?.registers, ["aa", "bb", "cc", "dd", "ee"])
            XCTAssertEqual(report.partialFacts?.measured?.cpu?.measurement.registers, ["aa", "bb", "cc", "dd", "ff"])
            XCTAssertEqual(report.partialFacts?.measured?.tlsPublicKeyFingerprint, "", "A key that the document doesn't endorse is empty.")
            XCTAssertEqual((error as? TinfoilError)?.verificationError?.layer, .policy)
            XCTAssertEqual(report.steps.map(\.status), [.passed, .passed, .passed, .failed])
        }
    }

    func testToleratesLayersAndStatusesThatItDoesNotKnow() throws {
        var result = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(payload().utf8)) as? [String: Any])
        var report = try XCTUnwrap(result["report"] as? [String: Any])
        report["steps"] = Self.passedSteps + [["layer": "device", "status": "skipped", "message": "no GPU"]]
        result["report"] = report
        let decoded = try decode(json(result))
        XCTAssertEqual(decoded.steps.last, Step(layer: VerificationLayer(rawValue: "device"), status: .skipped, message: "no GPU"))
    }

    func testRejectsAnInconsistentResult() throws {
        // No error, but no verified facts either.
        var result = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(payload().utf8)) as? [String: Any])
        var report = try XCTUnwrap(result["report"] as? [String: Any])
        report["verified_facts"] = nil
        report["partial_facts"] = [String: Any]()
        result["report"] = report
        assertAttestationError(try decode(json(result)), containing: "did not pass every step")

        // An error with verified facts.
        var accepted = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(payload().utf8)) as? [String: Any])
        accepted["error"] = ["layer": "policy", "message": "verification error: policy: rejected"]
        assertAttestationError(try decode(json(accepted)), containing: "carries verified facts")

        // An error without partial facts.
        var rejected = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(rejection().utf8)) as? [String: Any])
        var rejectedReport = try XCTUnwrap(rejected["report"] as? [String: Any])
        rejectedReport["partial_facts"] = nil
        rejected["report"] = rejectedReport
        assertAttestationError(try decode(json(rejected)), containing: "no partial facts")
    }

    func testADecodedReportEncodesItsJSONForm() throws {
        let report = try decode(payload([
            "config": ["source": "endorsement", "digest": "c0", "approval_time": "2026-09-20T08:00:00Z"],
        ]))
        let encoded = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any])
        let facts = try XCTUnwrap(encoded["verified_facts"] as? [String: Any])
        XCTAssertEqual(facts["code_measurement"] as? [String: String], ["platform": "tdx", "rtmr1": "bb", "rtmr2": "cc"])
        XCTAssertEqual(facts["config"] as? [String: String], ["source": "endorsement", "digest": "c0", "approval_time": "2026-09-20T08:00:00Z"])
        XCTAssertEqual(facts["freshness_expires_at"] as? String, "2026-10-03T12:00:00.5Z")
        XCTAssertNil(facts["tls_public_key_fp"], "The channel keys are only in crypto_material.")
        XCTAssertNil(facts["hpke_public_key"])
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
        XCTAssertEqual(
            classify("verification error: quote: rejected"),
            .attestation("quote: rejected"),
            "Without a report there is no verifier error to carry, so the layer stays in the message."
        )
        XCTAssertEqual(classify("verification error: rejected"), .attestation("rejected"))
        XCTAssertEqual(
            classify("unexpected"),
            .attestation("unexpected"),
            "An uncategorized verifier failure still fails closed."
        )
    }
}
