import XCTest
import Foundation
@testable import TinfoilAI

/// Exercises the real tinfoil-go verifier through the framework: the FFI
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
            if case .invalidConfiguration(let message) = error {
                XCTAssertFalse(message.hasPrefix("configuration error:"), "The Go prefix is dropped.", file: file, line: line)
            }
        }
    }

    private func isConfiguration(_ error: TinfoilError) -> Bool {
        if case .invalidConfiguration = error { return true }
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
            try verifier.verify(document: document, nonce: nonce, repo: Self.routerRepo, enclaveHost: "enclave.example")
        }
        assertCategory(isConfiguration) {
            try verifier.verify(document: document, nonce: nonce.dropFirst(), repo: Self.routerRepo, enclaveHost: "enclave.example")
        }
        assertCategory(isConfiguration) {
            try verifier.verify(document: document, nonce: nonce, repo: "owner", enclaveHost: "enclave.example")
        }
    }

    func testPolicyOptionsJSON() throws {
        XCTAssertEqual(try VerificationPolicy().optionsJSON(), "", "Defaults send no options.")
        XCTAssertEqual(
            try VerificationPolicy(freshnessMaxAge: 3600).optionsJSON(),
            #"{"freshness_max_age_ns":3600000000000}"#
        )
        let register = String(repeating: "ab", count: 48)
        let pinned = VerificationPolicy(
            pinnedRegisters: .init(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: ["", "", "", "", register])
        )
        XCTAssertNoThrow(try GoAttestationVerifier(policy: pinned), "Go accepts the pins the policy encodes.")
        XCTAssertNoThrow(try GoAttestationVerifier(policy: VerificationPolicy(freshnessMaxAge: 3600)))
    }

    func testAgesGoCannotRepresentAreRefusedWithoutTrapping() {
        for age in [TimeInterval.nan, .infinity, -.infinity, 1e300] {
            assertCategory(isConfiguration) { try VerificationPolicy(freshnessMaxAge: age).optionsJSON() }
            assertCategory(isConfiguration) { try GoAttestationVerifier(policy: VerificationPolicy(freshnessMaxAge: age)) }
        }
    }

    func testGoRejectsAnInvalidPolicy() {
        assertCategory(isConfiguration) { try GoAttestationVerifier(policy: VerificationPolicy(freshnessMaxAge: -1)) }
        assertCategory(isConfiguration) {
            try GoAttestationVerifier(policy: VerificationPolicy(pinnedRegisters: .init(type: "bogus", registers: ["aa"])))
        }
    }

    /// Attests the production router end to end: Swift fetches, Go verifies.
    func testLiveAttestation() async throws {
        try requireLiveIntegration()
        let attestor = Attestor(verifier: try GoAttestationVerifier())
        let verification = try await attestor.attest(
            host: TinfoilConstants.fallbackEnclave,
            relay: nil,
            repo: Self.routerRepo
        )

        XCTAssertEqual(verification.enclaveHost, TinfoilConstants.fallbackEnclave)
        XCTAssertEqual(verification.configRepo, Self.routerRepo)
        XCTAssertEqual(verification.hpkePublicKey?.count, 64)
        XCTAssertEqual(verification.tlsPublicKeyFingerprint.count, 64)
        XCTAssertGreaterThan(verification.freshnessExpiresAt, Date())
    }
}
