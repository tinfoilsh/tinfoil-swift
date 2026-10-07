import XCTest
import Foundation
@testable import TinfoilAI

/// Fingerprints of certificates generated with OpenSSL, against the SHA-256
/// of the SubjectPublicKeyInfo OpenSSL itself extracts.
final class CertificateFingerprintTests: XCTestCase {
    static let fixtures: [(name: String, der: String, spkiSHA256: String)] = [
        (
            "EC P-256",
            "MIIBhDCCASmgAwIBAgIUTkKactCh4WGRNRyxS7bqUVH6OXUwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMcDI1Ni5leGFtcGxlMB4XDTI2MTAwNzE4MDkxN1oXDTM2MTAwNDE4MDkxN1owFzEVMBMGA1UEAwwMcDI1Ni5leGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2HD05A+UM3VDGa+k/tUyrumogU5r/opiA6Z+Gv6xdmuAvtkjxzetgtOwcsMs6BA1YXnYBkGYBiizGfvz8sKAyKNTMFEwHQYDVR0OBBYEFDvYFrgUe0w6+MPEUvq8n3fWcbldMB8GA1UdIwQYMBaAFDvYFrgUe0w6+MPEUvq8n3fWcbldMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAMB/C/noln6npvbMv9AOdc7C68Wx3nWkXMEgJyl3p91DAiEAkgDVs7oms5DbfodI4q4lW0NH1ZFZqNUvktwMPlccsBA=",
            "6cf5107f5142c378b5c264f568eadb835f0d2dd273211fde0072e8550226f0a8"
        ),
        (
            "EC P-384",
            "MIIBvzCCAUagAwIBAgIUJzMUeZKJLZ8LIdzz6UztKsfhDmIwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMcDM4NC5leGFtcGxlMB4XDTI2MTAwNzE4MDkxN1oXDTM2MTAwNDE4MDkxN1owFzEVMBMGA1UEAwwMcDM4NC5leGFtcGxlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEBMOlaLNhQM3x6pCzKUMlVlj2Srm0fGRPPp4tPtJt8PtjDBhla8C6fuGXFEmUrULcs+xQU/7AoKENewngkTmeYLdpuW1bdjiVQAxG/DQCCq4GWWGIQxbMa74mWIiTZVj6o1MwUTAdBgNVHQ4EFgQUVKFuTeVk4jRI5l0QBjcCrFH7up0wHwYDVR0jBBgwFoAUVKFuTeVk4jRI5l0QBjcCrFH7up0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNnADBkAjAvVsO7V3YhQRErHLo2lqElBvxLHUpfqC18y4aXNaVSkCSPXWWgxME4sbybcn+HIkoCMBp1k5Ezoo/CtuPDs5Yu2ISlyY2wxyq+1mh1wAm2usMsD6cz78kjrCxOmgsV3wg3tA==",
            "2ce54006092669c60ac3e0039e5be5327ea22cf70961a4f8d16228e22e84ba83"
        ),
        (
            "RSA 2048",
            "MIIDDTCCAfWgAwIBAgIUb0LJqUdXiZ5GQl3C+O2S6JHk3cIwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLcnNhLmV4YW1wbGUwHhcNMjYxMDA3MTgwOTE3WhcNMzYxMDA0MTgwOTE3WjAWMRQwEgYDVQQDDAtyc2EuZXhhbXBsZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALgD0SGASbF2qmc5dmFcbngwHZLAhLFLHwTlaU+jwUSFSBKnYGl6N5teia4jcDosRTdWnuKuRLVYA7pHOcqIWpwDBXCf4uCbWTTLFE3x5rDTPvq5d9ZjRv1vKNoS3WHj77Ons50WjgzJ6Ql4IUEQNgeekcWcbtfzZHVFFwHtUilLhFOriWnLhEEO9N9eiMEFsYi213YCxTtnRTunqP9xNQxFvgRm9LtT5dUx4Tv6PskVopRHstIST73pLXkGJksnyFrcYbHJV/0L1lVrAg6FIHiri0DWh3X4TyNOCTu0zG/YYexM/ultsvyqQoKXXeNvYTOe/1y6ux/b4anOPpufouUCAwEAAaNTMFEwHQYDVR0OBBYEFH1jog4HPM5DyKyjfdworSwNaqJMMB8GA1UdIwQYMBaAFH1jog4HPM5DyKyjfdworSwNaqJMMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADJIHtPFwekQoQtFUQD/dcD7LagSFCfAqSLOqFzSnIThxuEx4jw9rsAurWe6YA0iSjeiBKAXKSzeh99QGiFeIz2+QhUYCCz01XOOmtgA8Kg1tXIRJfZ/nqR4GuM05WfopnycJWaC7kk2PU7EC7ib6jpaEpA0W788vrhgLkAECtEEUVbKM8dklsH2Jx4C5dpZsyzt6cBXfn+wRDObwVlW3im5Ez/FvAkuiME2LuixBzhBOHlJ/+QZPzHOE/yfzkFDkxriz6+tZnMdyx1a/QqEWYzxglwIGVcpCpxSFcTL4FsPRVhWaWE0GL/WocIQHx3I1czZBR6gqIW8hkgAa4R1tcM=",
            "eb8375a8952d5155b0465aac857111e1588ec31a8eb5d94eb575742ad3370bdd"
        ),
        (
            "Ed25519",
            "MIIBSDCB+6ADAgECAhQ55wGnjEyQEBCb6ndTLpQ1tmWZsTAFBgMrZXAwGjEYMBYGA1UEAwwPZWQyNTUxOS5leGFtcGxlMB4XDTI2MTAwNzE4MDkxN1oXDTM2MTAwNDE4MDkxN1owGjEYMBYGA1UEAwwPZWQyNTUxOS5leGFtcGxlMCowBQYDK2VwAyEAtfqyKsCXpH9nyxCJRs2wl38GMWs21DkyKf2X/2oQC5qjUzBRMB0GA1UdDgQWBBSN66gIkgawFF4+H7MU2fSCqCQRMTAfBgNVHSMEGDAWgBSN66gIkgawFF4+H7MU2fSCqCQRMTAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBAEAvksgF46ZcD8iu2Cq5bmxhySQGi/7fKAvIvaDIaoxsMdIi5aKyfh6Ke6mq33LxRDmZUsfD1k/hUuhRlpL5AQc=",
            "2634829565a9fecc91f7b3bea25085448e57285eba430fec10db89520ff60733"
        ),
        (
            "X.509 v1, version field omitted",
            "MIIBETCBuAIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDAp2MS5leGFtcGxlMB4XDTI2MTAwNzE4MDkzOFoXDTM2MTAwNDE4MDkzOFowFTETMBEGA1UEAwwKdjEuZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD7AaqvqkBxap97qSS2PEwvVW2LQO02/JskflF8ansmLf+8p1WM0SKo2XU1g4zoc2jT499DDklBMkPeme1TxIOIwCgYIKoZIzj0EAwIDSAAwRQIhAPXf5X6lks+U4aRLoAfHvGUhgeBZQj58OLgvftVMX6SwAiALgGWqA1NICma6Q66gcWQPm+3Av1xjT4bF5Lje56gmPg==",
            "870dc5c54078543f0e0275a82e7f8b0caf0b5d1c011550838e3c16df0dce7927"
        ),
    ]

    func testFingerprintsMatchOpenSSL() throws {
        for fixture in Self.fixtures {
            let der = try XCTUnwrap(Data(base64Encoded: fixture.der), fixture.name)
            XCTAssertEqual(try CertificateFingerprint.spkiSHA256(certificateDER: der), fixture.spkiSHA256, fixture.name)
        }
    }

    func testRejectsMalformedCertificates() throws {
        let der = try XCTUnwrap(Data(base64Encoded: Self.fixtures[0].der))
        for (name, bytes) in [
            ("empty", Data()),
            ("truncated", der.prefix(der.count / 2)),
            ("not a sequence", Data([0x02, 0x01, 0x00])),
            ("length past the end", Data([0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF])),
            ("too few fields", Data([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01])),
        ] {
            XCTAssertThrowsError(try CertificateFingerprint.spkiSHA256(certificateDER: bytes), name)
        }
    }
}
