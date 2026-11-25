#if TINFOIL_CONFORMANCE
import XCTest
import Foundation
import TinfoilGo
@testable import Tinfoil

/// Verifies the conformance vector of every golden case that names one,
/// through the framework and Swift's decoding, and checks that the report that
/// the SDK returns or throws encodes as the golden case. Step messages and
/// metadata are compared only by the cases that don't come from a vector
/// (ReportJSONTests), since a vector's are the run's own.
///
/// It needs a framework that was built with
/// `MOBILE_BUILD_TAGS=tinfoil_conformance`, whose test-only entry points take
/// a vector's trust anchors and clock, and the conformance suite's vectors:
///
///     TINFOIL_GO_XCFRAMEWORK=.build/TinfoilGo.xcframework \
///     TINFOIL_CONFORMANCE=1 \
///     TINFOIL_CONFORMANCE_VECTORS=/path/to/tinfoil-conformance/vectors \
///     swift test --filter ReportJSONVectorTests
final class ReportJSONVectorTests: XCTestCase {
    private struct Vector: Decodable {
        let input: Input

        struct Input: Decodable {
            let document_b64: String?
            let nonce_hex: String?
            let repo: String?
            let sigstore_trusted_root_json_b64: String?
            let amd_root_ca_pem: String?
            let ask_pem: String?
            let intel_sgx_root_pem: String?
            let verification_time_unix: Int64?
        }
    }

    func testEveryVectorBackedGoldenCase() throws {
        guard let directory = ProcessInfo.processInfo.environment["TINFOIL_CONFORMANCE_VECTORS"], !directory.isEmpty else {
            throw XCTSkip("set TINFOIL_CONFORMANCE_VECTORS to the conformance suite's vectors directory")
        }
        let cases = try ReportJSONGolden.all().filter { $0.vector != nil }
        XCTAssertEqual(cases.count, 7)
        for golden in cases {
            let file = URL(fileURLWithPath: directory).appendingPathComponent(try XCTUnwrap(golden.vector))
            let vector = try JSONDecoder().decode(Vector.self, from: Data(contentsOf: file))
            let report = try verify(vector.input, name: golden.name)
            let encoded = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any])
            JSONComparison.assertEqual(encoded, golden.report, ignoring: [.stepMessages, .metadata], golden.name)
        }
    }

    /// The report that the SDK returns for an accepted vector, or that its
    /// error carries for a rejected one
    private func verify(_ input: Vector.Input, name: String) throws -> VerificationReport {
        let roots = try JSONSerialization.data(withJSONObject: [
            "sigstore_trusted_root_json_b64": input.sigstore_trusted_root_json_b64,
            "amd_root_ca_pem": input.amd_root_ca_pem,
            "ask_pem": input.ask_pem,
            "intel_sgx_root_pem": input.intel_sgx_root_pem,
        ].compactMapValues { $0 })
        var error: NSError?
        let verifier = MobileNewDangerousTestOnlyVerifier(String(decoding: roots, as: UTF8.self), &error)
        if let error {
            throw error
        }
        let document = try XCTUnwrap(Data(base64Encoded: input.document_b64 ?? ""), "\(name): document")
        let nonce = try XCTUnwrap(Self.hex(input.nonce_hex ?? ""), "\(name): nonce")
        let at = try XCTUnwrap(input.verification_time_unix, "\(name): the vector is frozen")
        let payload = try XCTUnwrap(verifier).dangerousTestOnlyVerify(
            at: document, nonce: nonce, repo: input.repo ?? "", project: "", unixSeconds: at, error: &error
        )
        if let error {
            throw error
        }
        do {
            return try VerificationReport.decodeResult(payload, verificationPrefix: MobileVerificationErrorPrefix)
        } catch let failure as TinfoilError {
            return try XCTUnwrap(failure.verificationError?.report, "\(name): \(failure)")
        }
    }

    private static func hex(_ string: String) -> Data? {
        guard string.count.isMultiple(of: 2) else { return nil }
        var data = Data()
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            guard let byte = UInt8(string[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }
}
#endif
