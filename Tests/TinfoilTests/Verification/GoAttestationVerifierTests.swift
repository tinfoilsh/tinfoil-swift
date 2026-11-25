import XCTest
import Foundation
@testable import Tinfoil

/// Exercises the real TinfoilGo verifier through the framework: the FFI
/// types, the options JSON, and how each Go error category reaches Swift.
final class GoAttestationVerifierTests: XCTestCase {
    private static let routerRepo = TinfoilConstants.defaultGithubRepo

    private func assertCategory(
        _ expected: (TinfoilError) -> Bool,
        _ body: () throws -> Any,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            guard let error = error as? TinfoilError, expected(error) else {
                return XCTFail("unexpected error \(error)", file: file, line: line)
            }
            if case .configurationError(let failure) = error {
                XCTAssertFalse(failure.message.hasPrefix("usage error:"), "The Go prefix is dropped.", file: file, line: line)
            }
            if case .attestationError(let failure) = error {
                XCTAssertFalse(failure.message.hasPrefix("verification error:"), "The Go prefix is dropped.", file: file, line: line)
            }
        }
    }

    private func isConfiguration(_ error: TinfoilError) -> Bool {
        if case .configurationError = error { return true }
        return false
    }

    private func isAttestation(_ error: TinfoilError) -> Bool {
        if case .attestationError = error { return true }
        return false
    }

    func testNoncesAreFreshAndSized() throws {
        let verifier = try GoAttestationVerifier()
        let first = verifier.newNonce()
        XCTAssertEqual(first.count, 32)
        XCTAssertNotEqual(first, verifier.newNonce())
    }

    func testAttestationURLs() throws {
        let verifier = try GoAttestationVerifier()
        let nonce = verifier.newNonce()

        let direct = try verifier.attestationURL(host: "enclave.example", relay: nil, nonce: nonce)
        XCTAssertEqual(direct.absoluteString, "https://enclave.example/.well-known/tinfoil-attestation?nonce=\(nonce.hexString)")

        let relayed = try verifier.attestationURL(host: "enclave.example", relay: "relay.example:8443", nonce: nonce)
        XCTAssertEqual(
            relayed.absoluteString,
            "https://relay.example:8443/.well-known/tinfoil-attestation?nonce=\(nonce.hexString)&enclave=enclave.example"
        )

        assertCategory(isConfiguration) {
            try verifier.attestationURL(host: "https://enclave.example", relay: nil, nonce: nonce)
        }
    }

    func testVerifierErrorsKeepTheirCategory() throws {
        let verifier = try GoAttestationVerifier()
        let nonce = verifier.newNonce()
        let document = Data("{}".utf8)

        assertCategory(isAttestation) {
            try verifier.verify(document: document, nonce: nonce, pin: TinfoilConstants.routerPin)
        }
        XCTAssertThrowsError(
            try verifier.verify(document: document, nonce: nonce, pin: TinfoilConstants.routerPin)
        ) { error in
            guard case TinfoilError.attestationError(let failure) = error else {
                return XCTFail("unexpected error \(error)")
            }
            // The framework's result carries the report, which becomes the
            // cause of the attestation error.
            guard let rejected = failure.verificationError else {
                return XCTFail("the verifier's error and report must be the cause")
            }
            XCTAssertEqual(rejected.layer, .envelope, "A malformed document is rejected by the envelope layer.")
            XCTAssertEqual(rejected.message, failure.message)
            XCTAssertEqual(rejected.report.steps.map(\.layer), [.envelope, .provenance, .quote, .policy])
            XCTAssertEqual(rejected.report.steps.first?.status, .failed)
            XCTAssertTrue(
                rejected.report.steps.dropFirst().allSatisfy { $0.status == .notRun },
                "Verification stopped at the envelope: \(rejected.report.steps)"
            )
            XCTAssertNil(rejected.report.verifiedFacts)
            XCTAssertEqual(
                rejected.report.partialFacts,
                PartialFacts(expected: nil, measured: nil),
                "Nothing is established before the envelope passes."
            )
        }
        assertCategory(isConfiguration) {
            try verifier.verify(document: document, nonce: nonce.dropFirst(), pin: TinfoilConstants.routerPin)
        }
        assertCategory(isConfiguration) {
            try verifier.verify(document: document, nonce: nonce, pin: Pin(repo: "owner"))
        }
        assertCategory(isConfiguration) {
            try verifier.verify(document: document, nonce: nonce, pin: Pin(project: "owner"))
        }
    }

    /// Attests the production router end to end: Swift fetches, Go verifies.
    func testLiveAttestation() async throws {
        try requireLiveIntegration()
        let attestor = Attestor(verifier: try GoAttestationVerifier())
        let report = try await attestor.attest(
            host: TinfoilConstants.fallbackEnclave,
            relay: nil,
            pin: TinfoilConstants.routerPin
        )

        XCTAssertTrue(report.steps.allSatisfy { $0.status == .passed || $0.status == .skipped }, "\(report.steps)")
        XCTAssertNil(report.partialFacts)
        let verification = try XCTUnwrap(report.verifiedFacts)
        XCTAssertEqual(verification.configRepo, Self.routerRepo)
        XCTAssertEqual(verification.hpkePublicKey.count, 64)
        XCTAssertEqual(verification.tlsPublicKeyFingerprint.count, 64)
        XCTAssertGreaterThan(verification.freshnessExpiresAt, Date())
    }
}
