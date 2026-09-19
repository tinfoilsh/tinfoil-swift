import Foundation
import XCTest
@testable import TinfoilAI

final class PinningSecurityTests: XCTestCase {
    private static let register = String(repeating: "a", count: VerificationTestSupport.registerHexLength)
    private static let pin = AttestationMeasurement(
        type: VerificationTestSupport.sevGuestType,
        registers: [register]
    )

    func testEnclaveOriginsPreserveHostAndPort() throws {
        let cases: [(input: String, url: String, authority: String)] = [
            ("enclave.example", "https://enclave.example", "enclave.example"),
            ("ENCLAVE.example.:8443/path?query=value#fragment", "https://enclave.example:8443", "enclave.example:8443"),
            ("HTTPS://ENCLAVE.example:443", "https://enclave.example:443", "enclave.example:443"),
            ("https://127.0.0.1:8443", "https://127.0.0.1:8443", "127.0.0.1:8443"),
            ("[::1]:8443/path", "https://[::1]:8443", "[::1]:8443"),
            ("https://[::1]", "https://[::1]", "[::1]"),
            ("https://[2001:db8::1]:443", "https://[2001:db8::1]:443", "[2001:db8::1]:443"),
            ("https://[fe80::1%25en0]:8443", "https://[fe80::1%25en0]:8443", "[fe80::1%en0]:8443"),
            ("https://bücher.example:8443", "https://xn--bcher-kva.example:8443", "xn--bcher-kva.example:8443"),
            ("https://enclave.example:1", "https://enclave.example:1", "enclave.example:1"),
            ("https://enclave.example:65535", "https://enclave.example:65535", "enclave.example:65535"),
        ]

        for testCase in cases {
            let origin = try URLHelpers.parseEnclaveURL(testCase.input)
            XCTAssertEqual(origin.url, testCase.url, testCase.input)
            XCTAssertEqual(origin.authority, testCase.authority, testCase.input)
            let reparsed = try URLHelpers.parseEnclaveURL(origin.url)
            XCTAssertEqual(reparsed.url, origin.url, testCase.input)
            XCTAssertEqual(reparsed.authority, origin.authority, testCase.input)
        }
    }

    func testEnclaveOriginsRejectInvalidURLs() {
        let invalidURLs = [
            "", "/v1", "://", "https://", "https:///path", "https://.",
            "http://enclave.example:8443", "ftp://enclave.example", "wss://enclave.example",
            "mailto:user@example.com", "file:/tmp/enclave", "not a URL",
            "https://enclave.example:bad", "https://enclave.example:-1",
            "https://enclave.example:0", "https://enclave.example:65536",
            "https://enclave.example:999999999999999999999999",
            "https://user:password@enclave.example", "https://user@enclave.example",
            "https://[::1", "https://::1:8443",
        ]

        for url in invalidURLs {
            XCTAssertThrowsError(try URLHelpers.parseEnclaveURL(url), url) { error in
                XCTAssertTrue(error.localizedDescription.contains("enclaveURL"), url)
            }
        }
    }

    func testEnclaveOriginComparisonIncludesEffectivePort() throws {
        for host in ["enclave.example", "[::1]"] {
            let implicit = try URLHelpers.parseEnclaveURL("https://\(host)")
            let explicit = try URLHelpers.parseEnclaveURL("https://\(host):443")
            let custom = try URLHelpers.parseEnclaveURL("https://\(host):8443")
            XCTAssertEqual(URLHelpers.origin(from: implicit.url), URLHelpers.origin(from: explicit.url))
            XCTAssertNotEqual(URLHelpers.origin(from: implicit.url), URLHelpers.origin(from: custom.url))
        }

        let absoluteDNS = try URLHelpers.parseEnclaveURL("https://ENCLAVE.example.")
        let ordinaryDNS = try URLHelpers.parseEnclaveURL("https://enclave.example")
        let leadingDot = try URLHelpers.parseEnclaveURL("https://.enclave.example")
        XCTAssertEqual(absoluteDNS.url, ordinaryDNS.url)
        XCTAssertNotEqual(leadingDot.url, ordinaryDNS.url)
    }

    func testPinnedRefreshPreservesConfiguredOrigin() throws {
        for configured in ["ENCLAVE.example.:8443", "https://enclave.example:443", "https://[::1]:8443"] {
            let origin = try URLHelpers.parseEnclaveURL(configured)
            for baseURL: String? in [nil, "https://proxy.example"] {
                let refreshedURL = try XCTUnwrap(TinfoilAI.refreshEnclaveURL(
                    verifiedEnclaveURL: origin.url,
                    configuredEnclaveURL: configured,
                    baseURL: baseURL,
                    pinned: true
                ))
                XCTAssertEqual(refreshedURL, origin.url)
                XCTAssertEqual(try URLHelpers.parseEnclaveURL(refreshedURL).authority, origin.authority)
            }
        }
    }

    func testInvalidEnclaveOriginProducesPinnedFailureDocument() async {
        let client = SecureClient(
            enclaveURL: "http://enclave.example:8443",
            pinnedMeasurement: Self.pin
        )
        do {
            _ = try await client.verify()
            XCTFail("Non-HTTPS enclave URLs must fail before creating the Go verifier")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("enclaveURL"))
            XCTAssertNil(client.verifiedGroundTruth)
            XCTAssertEqual(client.verificationDocument?.securityVerified, false)
            XCTAssertEqual(client.verificationDocument?.steps.fetchDigest.status, .skipped)
            XCTAssertEqual(client.verificationDocument?.steps.verifyCode.status, .skipped)
            XCTAssertEqual(client.verificationDocument?.steps.otherError?.status, .failed)
        }
    }

    func testPinnedFailureDocumentsSkipProvenanceForEveryFailurePath() {
        let localErrors: [Error] = [
            VerificationError.verificationFailed("Document does not match ground truth"),
            VerificationError.jsonDecodingFailed("Missing provenance"),
            DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Invalid document")),
            CancellationError(),
        ]
        var failures = localErrors.map {
            VerificationDocument.Steps(otherError: .failed($0.localizedDescription))
        }
        failures += [
            "invalid pinned measurement: wrong register count",
            "reference values: verifying platform endorsements: invalid signature",
            "cpu evidence: invalid report",
            "cpu evidence: no matching platform",
            "measurements: mismatch",
            "binding: missing key",
        ].map { SecureClient.stepsFromError($0, pinnedMeasurement: true) }
        failures.append(.init(
            verifyEnclave: .success(),
            compareMeasurements: .success(),
            verifyCertificate: .failed("certificate"),
            createTransport: .failed("transport"),
            verifyHPKEKey: .failed("key"),
            otherError: .failed("other")
        ))

        for steps in failures {
            let document = SecureClient.makeFailureDocument(
                configRepo: TinfoilConstants.pinnedNoRepo,
                enclaveHost: "enclave.example:8443",
                pinnedMeasurement: Self.pin,
                steps: steps
            )
            XCTAssertFalse(document.securityVerified)
            XCTAssertFalse(document.allStepsSucceeded)
            XCTAssertEqual(document.configRepo, TinfoilConstants.pinnedNoRepo)
            XCTAssertEqual(document.releaseDigest, TinfoilConstants.pinnedNoDigest)
            XCTAssertEqual(document.codeMeasurement.type, Self.pin.type)
            XCTAssertEqual(document.codeMeasurement.registers, Self.pin.registers)
            XCTAssertEqual(document.enclaveHost, "enclave.example:8443")
            XCTAssertEqual(document.selectedRouterEndpoint, document.enclaveHost)
            XCTAssertEqual(document.steps.fetchDigest.status, .skipped)
            XCTAssertEqual(document.steps.verifyCode.status, .skipped)
            XCTAssertTrue(document.tlsPublicKey.isEmpty)
            XCTAssertTrue(document.hpkePublicKey.isEmpty)

            let preserved: [(VerificationStepState?, VerificationStepState?)] = [
                (document.steps.verifyEnclave, steps.verifyEnclave),
                (document.steps.compareMeasurements, steps.compareMeasurements),
                (document.steps.verifyCertificate, steps.verifyCertificate),
                (document.steps.createTransport, steps.createTransport),
                (document.steps.verifyHPKEKey, steps.verifyHPKEKey),
                (document.steps.otherError, steps.otherError),
            ]
            for (actual, expected) in preserved {
                XCTAssertEqual(actual?.status, expected?.status)
                XCTAssertEqual(actual?.error, expected?.error)
            }
        }
    }

    func testNonPinnedFailureDocumentsPreserveFailedCodeVerification() {
        let error = "reference values: verifying code measurement: invalid signature"
        let steps = SecureClient.stepsFromError(error)
        let document = SecureClient.makeFailureDocument(
            configRepo: "owner/repo",
            enclaveHost: "enclave.example",
            pinnedMeasurement: nil,
            steps: steps
        )
        XCTAssertFalse(document.securityVerified)
        XCTAssertEqual(document.steps.fetchDigest.status, .skipped)
        XCTAssertEqual(document.steps.verifyCode.status, .failed)
        XCTAssertEqual(document.steps.verifyCode.error, error)
        XCTAssertTrue(document.releaseDigest.isEmpty)
        XCTAssertTrue(document.codeMeasurement.registers.isEmpty)
    }

    func testVMShapeEncodesGoJSONFieldNames() throws {
        let shape = VMShape(cpus: 8, memoryMB: 32768, disks: 1, gpus: 2)
        let data = try JSONEncoder().encode(shape)
        let object = try JSONDecoder().decode([String: Int].self, from: data)
        XCTAssertEqual(object, ["cpus": 8, "memory_mb": 32768, "disks": 1, "gpus": 2])

        // gpus is optional in Go's policy.Shape and must be omitted, not null.
        let noGPU = try JSONEncoder().encode(VMShape(cpus: 1, memoryMB: 1, disks: 1))
        let noGPUObject = try JSONDecoder().decode([String: Int].self, from: noGPU)
        XCTAssertNil(noGPUObject["gpus"])
        XCTAssertEqual(noGPUObject.count, 3)
    }

    func testLegacyHardwareMeasurementsReencodeWithGoFieldNames() throws {
        let data = try JSONEncoder().encode([
            "id": "platform@digest", "mrtd": Self.register, "rtmr0": Self.register,
        ])
        let hardware = try JSONDecoder().decode(HardwareMeasurement.self, from: data)
        let encoded = try JSONEncoder().encode(hardware)
        XCTAssertEqual(try JSONDecoder().decode([String: String].self, from: encoded), [
            "ID": hardware.id, "MRTD": hardware.mrtd, "RTMR0": hardware.rtmr0,
        ])
    }

    func testPinnedMeasurementEncodesGoJSONFieldNames() throws {
        let data = try JSONEncoder().encode(Self.pin)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(object.keys), Set(["type", "registers"]))
        XCTAssertEqual(object["type"] as? String, Self.pin.type)
        XCTAssertEqual(object["registers"] as? [String], Self.pin.registers)
    }
}
