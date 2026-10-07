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
            XCTAssertEqual(SecTrustSetAnchorCertificates(created, [certificate] as CFArray), errSecSuccess)
            XCTAssertEqual(SecTrustSetAnchorCertificatesOnly(created, true), errSecSuccess)
        }
        return created
    }

    private func rejection(_ delegate: PinningDelegate) throws -> PinnedTLS.Rejection {
        try XCTUnwrap(delegate.failure as? PinnedTLS.Rejection, "expected a rejection, got \(String(describing: delegate.failure))")
    }

    private func tlsError(_ delegate: PinningDelegate) throws -> URLError {
        try XCTUnwrap(delegate.failure as? URLError, "expected a URLError, got \(String(describing: delegate.failure))")
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
        let space = URLProtectionSpace(
            host: "enclave.example", port: 443, protocol: NSURLProtectionSpaceHTTPS,
            realm: nil, authenticationMethod: NSURLAuthenticationMethodServerTrust
        )
        XCTAssertNil(space.serverTrust)
        let challenge = URLAuthenticationChallenge(
            protectionSpace: space, proposedCredential: nil, previousFailureCount: 0,
            failureResponse: nil, error: nil, sender: IgnoredSender()
        )
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }

        var disposition: URLSession.AuthChallengeDisposition?
        delegate.urlSession(session, didReceive: challenge) { chosen, _ in disposition = chosen }

        XCTAssertEqual(disposition, .cancelAuthenticationChallenge)
        XCTAssertEqual(try tlsError(delegate).code, .secureConnectionFailed)
    }

    func testAnUntrustedCertificateIsRefusedEvenWithTheAttestedKey() throws {
        let p256 = try fixture("EC P-256")
        let delegate = PinningDelegate(fingerprint: p256.fingerprint, origin: "https://enclave.example:443")

        XCTAssertFalse(delegate.admit(try trust(p256.der, anchored: false), host: "enclave.example"))
        // Verifying the enclave again cannot fix it, so it is not a rejection.
        XCTAssertEqual(try tlsError(delegate).code, .serverCertificateUntrusted)
    }
}

private final class IgnoredSender: NSObject, URLAuthenticationChallengeSender {
    func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
    func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
    func cancel(_ challenge: URLAuthenticationChallenge) {}
}
