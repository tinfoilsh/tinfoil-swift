import XCTest
import Foundation
import Security
@testable import TinfoilAI

/// The pinning delegate's decision on real trust objects, built from the
/// certificate fixtures and anchored to themselves so they evaluate as trusted.
final class PinningDelegateTests: XCTestCase {
    private func fixture(_ name: String) throws -> (der: Data, fingerprint: String) {
        let fixture = try XCTUnwrap(CertificateFingerprintTests.fixtures.first { $0.name == name })
        return (try XCTUnwrap(Data(base64Encoded: fixture.der)), fixture.spkiSHA256)
    }

    private func trust(_ der: Data, anchored: Bool = true) throws -> SecTrust {
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil, der as CFData))
        var trust: SecTrust?
        XCTAssertEqual(SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust), errSecSuccess)
        let created = try XCTUnwrap(trust)
        if anchored {
            SecTrustSetAnchorCertificates(created, [certificate] as CFArray)
            SecTrustSetAnchorCertificatesOnly(created, true)
        }
        return created
    }

    private func rejection(_ delegate: PinningDelegate) throws -> PinnedTLS.Rejection {
        try XCTUnwrap(delegate.failure as? PinnedTLS.Rejection, "expected a rejection, got \(String(describing: delegate.failure))")
    }

    func testTheAttestedKeyIsAdmitted() throws {
        let p256 = try fixture("EC P-256")
        let delegate = PinningDelegate(fingerprint: p256.fingerprint, origin: "https://enclave.example:443")

        XCTAssertTrue(delegate.admit(try trust(p256.der), host: "enclave.example"))
        XCTAssertNil(delegate.failure)
    }

    func testAnotherKeyOnTheFirstConnectionMeansNothingWasSent() throws {
        let p256 = try fixture("EC P-256")
        let p384 = try fixture("EC P-384")
        let delegate = PinningDelegate(fingerprint: p256.fingerprint, origin: "https://enclave.example:443")

        XCTAssertFalse(delegate.admit(try trust(p384.der), host: "enclave.example"))

        let rejection = try rejection(delegate)
        XCTAssertTrue(rejection.reason.contains("does not match the attestation"))
        XCTAssertFalse(rejection.requestMayHaveBeenSent)
    }

    func testAnotherKeyAfterAPinnedConnectionMayFollowASentRequest() throws {
        let p256 = try fixture("EC P-256")
        let p384 = try fixture("EC P-384")
        let delegate = PinningDelegate(fingerprint: p256.fingerprint, origin: "https://enclave.example:443")

        XCTAssertTrue(delegate.admit(try trust(p256.der), host: "enclave.example"))
        XCTAssertFalse(delegate.admit(try trust(p384.der), host: "enclave.example"))

        XCTAssertTrue(try rejection(delegate).requestMayHaveBeenSent)
    }

    func testAChallengeWithoutTrustIsRefused() throws {
        let delegate = PinningDelegate(fingerprint: try fixture("EC P-256").fingerprint, origin: "https://enclave.example:443")

        XCTAssertFalse(delegate.admit(nil, host: "enclave.example"))
        XCTAssertTrue(try rejection(delegate).reason.contains("no certificate"))
    }

    func testAnUntrustedCertificateIsRefusedEvenWithTheAttestedKey() throws {
        let p256 = try fixture("EC P-256")
        let delegate = PinningDelegate(fingerprint: p256.fingerprint, origin: "https://enclave.example:443")

        XCTAssertFalse(delegate.admit(try trust(p256.der, anchored: false), host: "enclave.example"))
        XCTAssertTrue(try rejection(delegate).reason.contains("not trusted"))
    }
}
