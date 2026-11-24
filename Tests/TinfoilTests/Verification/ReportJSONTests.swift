import XCTest
import Foundation
@testable import Tinfoil

/// The golden cases of the report's JSON form, copied unchanged from
/// tinfoil-go's verify/testdata/report-json (tinfoilsh/tinfoil-go#346, at
/// b0d37b8). Each file has a `description`, the expected `report`, and, for a
/// case that verifying a conformance vector gives, the `vector`.
struct ReportJSONGolden {
    let name: String
    let description: String
    let vector: String?
    let report: [String: Any]

    static func all() throws -> [ReportJSONGolden] {
        let directory = try XCTUnwrap(
            Bundle.module.url(forResource: "report-json", withExtension: nil),
            "the golden files are a resource of the test target"
        )
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        return try files.map { file in
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
            return ReportJSONGolden(
                name: file.deletingPathExtension().lastPathComponent,
                description: try XCTUnwrap(object["description"] as? String),
                vector: object["vector"] as? String,
                report: try XCTUnwrap(object["report"] as? [String: Any])
            )
        }
    }

    static func named(_ name: String) throws -> ReportJSONGolden {
        try XCTUnwrap(all().first { $0.name == name }, "no golden case \(name)")
    }
}

/// Compares JSON values as the golden files' README says: as values, not
/// bytes, with times compared as instants. Another SDK's step messages and
/// metadata are its own, so `ignoring` leaves them out where the report
/// didn't come from the same input.
enum JSONComparison {
    /// The members that hold times
    private static let timeMembers: Set = ["verified_at", "freshness_expires_at", "approval_time", "signature_time"]

    struct Ignored: OptionSet {
        let rawValue: Int
        static let stepMessages = Ignored(rawValue: 1)
        static let metadata = Ignored(rawValue: 2)
    }

    static func assertEqual(
        _ got: Any,
        _ want: Any,
        ignoring ignored: Ignored = [],
        _ context: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        compare(got, want, path: "$", member: nil, ignored: ignored).forEach {
            XCTFail("\(context): \($0)", file: file, line: line)
        }
    }

    private static func compare(_ got: Any, _ want: Any, path: String, member: String?, ignored: Ignored) -> [String] {
        switch (got, want) {
        case let (got as [String: Any], want as [String: Any]):
            var keys = Set(got.keys).union(want.keys)
            if ignored.contains(.metadata), path == "$" {
                keys.remove("metadata")
            }
            if ignored.contains(.stepMessages), path.hasPrefix("$.steps[") {
                keys.remove("message")
            }
            return keys.sorted().flatMap { key -> [String] in
                switch (got[key], want[key]) {
                case let (got?, want?):
                    return compare(got, want, path: "\(path).\(key)", member: key, ignored: ignored)
                case (nil, _):
                    return ["\(path).\(key) is missing"]
                case (_, nil):
                    return ["\(path).\(key) is unexpected"]
                }
            }
        case let (got as [Any], want as [Any]):
            guard got.count == want.count else {
                return ["\(path) has \(got.count) items, want \(want.count)"]
            }
            return zip(got, want).enumerated().flatMap { index, pair in
                compare(pair.0, pair.1, path: "\(path)[\(index)]", member: nil, ignored: ignored)
            }
        case let (got as String, want as String) where member.map(timeMembers.contains) == true:
            guard let gotTime = ReportTime.parse(got), let wantTime = ReportTime.parse(want) else {
                return ["\(path) is \(got), want \(want), and they are not both times"]
            }
            // Date holds an instant to about a microsecond.
            return abs(gotTime.timeIntervalSince(wantTime)) < 0.000_001 ? [] : ["\(path) is \(got), want \(want)"]
        case let (got as NSNumber, want as NSNumber):
            return got == want ? [] : ["\(path) is \(got), want \(want)"]
        case let (got as String, want as String):
            return got == want ? [] : ["\(path) is \(got), want \(want)"]
        default:
            return ["\(path) is \(got), want \(want)"]
        }
    }
}

/// The JSON form of a verification report, which `JSONEncoder` writes from a
/// `VerificationReport` and its facts
final class ReportJSONTests: XCTestCase {
    private func json(_ value: some Encodable) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
    }

    /// The bridge's result for a report in the JSON form: the report
    /// unchanged, with the error of its failed step, if one failed
    private func bridgeResult(for report: [String: Any]) throws -> String {
        var result: [String: Any] = ["schema_version": 3, "report": report]
        let steps = try XCTUnwrap(report["steps"] as? [[String: Any]])
        if let failed = steps.first(where: { $0["status"] as? String == "failed" }) {
            let layer = try XCTUnwrap(failed["layer"] as? String)
            let message = failed["message"] as? String ?? ""
            result["error"] = ["layer": layer, "message": "verification error: \(layer): \(message)"]
        }
        return String(decoding: try JSONSerialization.data(withJSONObject: result), as: UTF8.self)
    }

    /// The report that the SDK returns or throws for a bridge result
    private func decodedReport(_ result: String) throws -> VerificationReport {
        do {
            return try VerificationReport.decodeResult(result, verificationPrefix: "verification error: ")
        } catch let error as TinfoilError {
            return try XCTUnwrap(error.verificationError?.report, "\(error)")
        }
    }

    /// Every golden case, as the bridge would carry it, decodes into a report
    /// that encodes as the case: the framework's report reaches a caller's
    /// JSON unchanged. The SDK names itself as the verifier, which the
    /// framework can't.
    func testEveryGoldenCaseSurvivesTheBridge() throws {
        let cases = try ReportJSONGolden.all()
        XCTAssertEqual(cases.count, 10)
        for golden in cases {
            let report = try decodedReport(bridgeResult(for: golden.report))
            let encoded = try json(report)
            JSONComparison.assertEqual(encoded, golden.report, ignoring: .metadata, golden.name)

            let metadata = try XCTUnwrap(encoded["metadata"] as? [String: Any])
            let wantMetadata = try XCTUnwrap(golden.report["metadata"] as? [String: Any])
            JSONComparison.assertEqual(metadata["verified_at"] as Any, wantMetadata["verified_at"] as Any, golden.name)
            XCTAssertEqual(
                metadata["verifier"] as? [String: String],
                ["name": "tinfoil-swift", "version": TinfoilConstants.sdkVersion],
                golden.name
            )
        }
    }

    /// The facts of acceptance-config-facts, built in Swift as Go's
    /// goldenConfigFacts builds them, and given times off UTC, which the form
    /// writes in UTC
    func testConfigFactsGolden() throws {
        let golden = try ReportJSONGolden.named("acceptance-config-facts")
        let approved = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-09-20T03:00:00-05:00")).addingTimeInterval(0.000_000_5)
        let launch = "abcd" + String(repeating: "0", count: 92)
        let digest = String(repeating: "0a", count: 32)
        let facts = VerifiedFacts(
            configRepo: "tinfoilsh/cvmimage",
            codeDigest: digest,
            codeTag: "v0.15.0",
            codeMeasurement: .init(type: "https://tinfoil.sh/predicate/sev-snp-guest/v2", registers: [launch]),
            enclaveMeasurement: .init(type: "https://tinfoil.sh/predicate/sev-snp-guest/v2", registers: [launch.uppercased()]),
            config: ConfigVerification(
                source: .endorsement, name: "/org/project/v1", digest: String(repeating: "0c", count: 32),
                reference: "org/project@v1", signingKeyHint: "hint", approvalTime: approved,
                registryID: "registry", signatureTime: approved.addingTimeInterval(60)
            ),
            runtime: ArtifactVerification(
                source: .endorsement, repo: "tinfoilsh/cvmimage", tag: "v0.15.0", digest: digest,
                name: "runtime", commit: String(repeating: "0e", count: 20), approvalTime: approved
            ),
            platform: ArtifactVerification(
                source: .embedded, repo: "", tag: "", digest: String(repeating: "0f", count: 32),
                name: "", commit: "", approvalTime: nil
            ),
            tlsPublicKeyFingerprint: String(repeating: "ab", count: 32),
            hpkePublicKey: String(repeating: "11", count: 32),
            cryptoMaterial: [
                .init(id: "tls", format: VerifiedFacts.CryptoMaterial.tlsFormat, data: String(repeating: "ab", count: 32)),
                .init(id: "hpke", format: VerifiedFacts.CryptoMaterial.hpkeFormat, data: String(repeating: "11", count: 32)),
            ],
            freshnessExpiresAt: Date(timeIntervalSince1970: 1_791_028_800)
        )
        let report = VerificationReport(
            steps: ["envelope", "provenance", "quote", "policy"].map {
                Step(layer: VerificationLayer(rawValue: $0), status: .passed, message: "")
            },
            verifiedFacts: facts,
            partialFacts: nil,
            metadata: VerificationMetadata(
                verifier: SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion),
                verifiedAt: try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-01-02T03:04:05+01:00"))
            )
        )
        let encoded = try json(report)
        JSONComparison.assertEqual(encoded, golden.report, ignoring: .metadata, golden.name)
        XCTAssertEqual((encoded["metadata"] as? [String: Any])?["verified_at"] as? String, "2026-01-02T02:04:05Z")
        // The facts encode on their own as they do within the report.
        JSONComparison.assertEqual(try json(facts), try XCTUnwrap(golden.report["verified_facts"]), "facts alone")
    }

    func testAReportWritesTheMembersOfTheForm() throws {
        let encoded = try json(VerificationReport.stub(expiresAt: Date(timeIntervalSince1970: 1_791_028_800.25)))
        XCTAssertEqual(Set(encoded.keys), ["schema_version", "steps", "verified_facts", "metadata"])
        XCTAssertEqual(encoded["schema_version"] as? Int, 1)
        XCTAssertEqual(encoded["steps"] as? [[String: String]], ["envelope", "provenance", "quote", "policy"].map {
            ["layer": $0, "status": "passed"]
        }, "A step without a message has none.")
        let facts = try XCTUnwrap(encoded["verified_facts"] as? [String: Any])
        XCTAssertEqual(
            Set(facts.keys),
            ["config_repo", "code_digest", "crypto_material", "freshness_expires_at"],
            "Empty and nil facts are omitted, and the channel keys are only in crypto_material."
        )
        XCTAssertEqual(facts["freshness_expires_at"] as? String, "2026-10-03T12:00:00.25Z")
    }

    func testARejectedReportWritesItsPartialFacts() throws {
        let report = try XCTUnwrap(VerificationReport.rejection(layer: .quote, message: "quote: bad signature").verificationError?.report)
        let encoded = try json(report)
        XCTAssertNil(encoded["verified_facts"])
        XCTAssertEqual(
            encoded["partial_facts"] as? [String: [String: String]],
            ["measured": ["tls_public_key_fp": "deadbeef"]],
            "Facts that were not established are omitted."
        )
        let steps = try XCTUnwrap(encoded["steps"] as? [[String: String]])
        XCTAssertEqual(steps.map { $0["status"] }, ["passed", "passed", "failed", "not_run"])
        XCTAssertNotNil(steps[2]["message"])

        let envelope = try XCTUnwrap(VerificationReport.rejection(layer: .envelope, message: "envelope: bad nonce").verificationError?.report)
        XCTAssertEqual(try json(envelope)["partial_facts"] as? [String: String], [:], "A failed report keeps its empty partial facts.")
        XCTAssertEqual(
            try json(MeasuredFacts(cpu: nil, tlsPublicKeyFingerprint: "", hpkePublicKeyFingerprint: "")) as? [String: String],
            [:],
            "Measured facts without a key stay as {}."
        )
    }

    func testMeasurementsNameTheirRegisters() throws {
        let tdx = VerifiedFacts.Measurement(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: ["", "", "BB", "cc", ""])
        XCTAssertEqual(try json(tdx) as? [String: String], ["platform": "tdx", "rtmr1": "bb", "rtmr2": "cc"])
        let snp = VerifiedFacts.Measurement(type: "https://tinfoil.sh/predicate/sev-snp-guest/v2", registers: ["aa"])
        XCTAssertEqual(try json(snp) as? [String: String], ["platform": "sev-snp", "launch": "aa"])

        for measurement in [
            VerifiedFacts.Measurement(type: "bogus", registers: ["aa"]),
            VerifiedFacts.Measurement(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: ["aa"]),
        ] {
            XCTAssertThrowsError(try JSONEncoder().encode(measurement)) { error in
                guard case EncodingError.invalidValue = error else {
                    return XCTFail("expected an invalid value, got \(error)")
                }
            }
        }
    }

    func testACodeMeasurementWithoutARegisterIsOmitted() throws {
        let unconstrained = VerifiedFacts.Measurement(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: ["", "", "", "", ""])
        let expected = ExpectedFacts(
            configRepo: "org/repo",
            artifact: ArtifactVerification(source: .embedded, repo: "", tag: "", digest: "aa", name: "", commit: "", approvalTime: nil),
            config: nil,
            platform: nil,
            codeMeasurement: unconstrained,
            measurement: nil
        )
        XCTAssertEqual(
            try json(expected) as NSDictionary,
            ["config_repo": "org/repo", "artifact": ["source": "embedded", "digest": "aa"]] as NSDictionary
        )
    }

    func testTimesAreUTCWithAtMostMicroseconds() {
        for (seconds, text) in [
            (1_791_028_800.0, "2026-10-03T12:00:00Z"),
            (1_791_028_800.5, "2026-10-03T12:00:00.5Z"),
            (1_791_028_800.123_456, "2026-10-03T12:00:00.123456Z"),
            (1_791_028_800.000_010, "2026-10-03T12:00:00.00001Z"),
            (-0.5, "1969-12-31T23:59:59.5Z"),
        ] {
            XCTAssertEqual(ReportTime.format(Date(timeIntervalSince1970: seconds)), text)
            XCTAssertEqual(ReportTime.parse(text)?.timeIntervalSince1970 ?? .nan, seconds, accuracy: 0.000_001, text)
        }
        XCTAssertEqual(
            ReportTime.parse("2026-09-20T08:00:00.0000005Z")?.timeIntervalSince1970 ?? .nan,
            1_789_891_200.000_000_5,
            accuracy: 0.000_001,
            "A fraction longer than Foundation's milliseconds is read in full."
        )
        for invalid in ["next week", "2026-10-03T12:00:00.Z", ""] {
            XCTAssertNil(ReportTime.parse(invalid), invalid)
        }
    }
}
