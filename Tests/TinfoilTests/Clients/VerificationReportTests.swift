import XCTest
import Foundation
@testable import Tinfoil

/// How the clients report each verification attempt through
/// `lastVerification` and `onVerification`: the conformance cases of the
/// verification lifecycle, against the stand-ins from
/// AttestationTestDoubles.swift.
final class VerificationReportTests: XCTestCase {
    private typealias Attempt = (host: String, result: Result<VerificationReport, TinfoilError>)

    private let rejection = PinnedTLS.Rejection(host: "enclave.example", reason: "presented a certificate whose key does not match the attestation")

    /// A TLS connection to enclave.example whose attestation source is
    /// network and whose pinned sends go to send. It verifies lazily.
    private func connection(
        _ network: FakeNetwork,
        verificationCheck: VerificationCheck? = nil,
        onVerification: VerificationCallback? = nil,
        send: @escaping PinnedTLS.Send = { request, _ in
            (Data("ok".utf8), HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        }
    ) throws -> EnclaveConnection {
        try EnclaveConnection(
            handle: EnclaveHandle(
                enclave: "enclave.example",
                pin: Pin(repo: "org/repo"),
                attestationRelay: nil,
                attestor: Attestor(
                    verifier: FakeVerifier(),
                    fetch: { try network.fetch($0) },
                    retryDelay: 0,
                    verificationCheck: verificationCheck
                ),
                onVerification: onVerification
            ),
            transportMode: .tls,
            baseURL: nil,
            userCacheSecret: "",
            send: send
        )
    }

    /// An attestation source that serves each verdict in turn, and the last
    /// one from then on
    private func serving(_ verdicts: String...) -> FakeNetwork {
        FakeNetwork { url, previous in
            if url == TinfoilConstants.routerListURL {
                return #"["router-a.example","router-b.example"]"#
            }
            let verdict = verdicts[min(previous, verdicts.count - 1)]
            if verdict == "offline" {
                throw TinfoilError.network("attestation source unreachable")
            }
            return FakeNetwork.document(verdict, for: url)
        }
    }

    func testASuccessfulVerificationIsTheLastAndIsReportedOnce() async throws {
        let attempts = Recorder<Attempt>()
        let client = try await EnclaveHTTPClient(verifying: connection(serving("ok"), onVerification: { attempts.record(($0, $1)) }))

        let report = try await client.ensureVerified()
        XCTAssertNotNil(report.verifiedFacts)
        XCTAssertNil(report.partialFacts)
        let last = await client.lastVerification
        XCTAssertEqual(last?.report, report)
        XCTAssertEqual(attempts.values.count, 1, "The verification at creation is reported once.")
        XCTAssertEqual(attempts.values.first?.host, "enclave.example")
        XCTAssertEqual(attempts.values.first?.result.report, report)
    }

    func testARejectedDocumentCarriesTheVerifierErrorAndReport() async throws {
        let attempts = Recorder<Attempt>()
        let connection = try connection(serving("reject"), onVerification: { attempts.record(($0, $1)) })

        let thrown: TinfoilError
        do {
            _ = try await connection.ensureUsable()
            return XCTFail("a rejected document must fail verification")
        } catch let error as TinfoilError {
            thrown = error
        }

        guard case .attestationError = thrown, let rejected = thrown.verificationError else {
            return XCTFail("expected an attestation error caused by the verifier's error, got \(thrown)")
        }
        XCTAssertEqual(rejected.report.steps.first { $0.status == .failed }?.layer, rejected.layer)
        XCTAssertNil(rejected.report.verifiedFacts)
        XCTAssertNotNil(rejected.report.partialFacts)
        let last = await connection.lastVerification
        XCTAssertNil(last?.report)
        XCTAssertEqual(last?.error, thrown, "lastVerification returns the error that the client reported.")
        XCTAssertEqual(attempts.values.count, 2, "The failed attempt and its retry are each reported.")
        XCTAssertTrue(attempts.values.allSatisfy { $0.host == "enclave.example" && $0.result.error?.verificationError != nil })
        XCTAssertEqual(attempts.values.last?.result.error, thrown)
    }

    func testAFailedFetchIsANetworkErrorWithoutAReport() async throws {
        let attempts = Recorder<Attempt>()
        let connection = try connection(serving("offline"), onVerification: { attempts.record(($0, $1)) })

        do {
            _ = try await connection.ensureUsable()
            XCTFail("an unreachable attestation source must fail verification")
        } catch let error as TinfoilError {
            guard case .networkError = error else {
                return XCTFail("expected a network error, got \(error)")
            }
            XCTAssertNil(error.verificationError, "An attempt that failed before the verifier ran has no report.")
            let last = await connection.lastVerification
            XCTAssertEqual(last?.error, error)
            XCTAssertEqual(attempts.values.last?.result.error, error)
        }
    }

    func testAFailedReverificationReplacesAnEarlierSuccess() async throws {
        let client = try await EnclaveHTTPClient(verifying: connection(serving("ok", "reject")))
        let first = await client.lastVerification
        XCTAssertNotNil(first?.report)

        _ = try? await client.reverify()

        let last = await client.lastVerification
        XCTAssertNil(last?.report, "The earlier success is not returned in place of the failure.")
        XCTAssertNotNil(last?.error?.verificationError)
    }

    func testEachAttemptOfARetriedVerificationIsReported() async throws {
        let attempts = Recorder<Attempt>()
        let client = try await EnclaveHTTPClient(verifying: connection(serving("reject", "ok"), onVerification: { attempts.record(($0, $1)) }))

        XCTAssertEqual(attempts.values.count, 2)
        XCTAssertNotNil(attempts.values.first?.result.error?.verificationError, "The failed attempt is reported first.")
        let last = await client.lastVerification
        XCTAssertNotNil(last?.report, "lastVerification returns the retry.")
        XCTAssertEqual(attempts.values.last?.result.report, last?.report)
    }

    func testAKeyRotationReportsTheReverification() async throws {
        let attempts = Recorder<Attempt>()
        let sends = Recorder<String>()
        let connection = try connection(serving("ok"), onVerification: { attempts.record(($0, $1)) }, send: { request, fingerprint in
            if sends.record(fingerprint) == 1 {
                throw self.rejection
            }
            return (Data("ok".utf8), HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
        })

        _ = try await connection.data(from: URL(string: "/health")!)

        XCTAssertEqual(sends.values.count, 2, "The request was retried once after the re-verification.")
        XCTAssertEqual(attempts.values.count, 2, "The first verification and the re-verification are each reported.")
        XCTAssertEqual(attempts.values.map(\.host), ["enclave.example", "enclave.example"])
        XCTAssertNotEqual(attempts.values.first?.result.report, attempts.values.last?.result.report)
    }

    func testConcurrentRequestsShareOneReportedVerification() async throws {
        let attempts = Recorder<Attempt>()
        let gate = AsyncGate()
        let network = serving("ok")
        let connection = try EnclaveConnection(
            handle: EnclaveHandle(
                enclave: "enclave.example",
                pin: Pin(repo: "org/repo"),
                attestationRelay: nil,
                attestor: Attestor(verifier: FakeVerifier(), fetch: { url in
                    await gate.wait()
                    return try network.fetch(url)
                }, retryDelay: 0),
                onVerification: { attempts.record(($0, $1)) }
            ),
            transportMode: .tls,
            baseURL: nil,
            userCacheSecret: "",
            send: { request, _ in
                (Data("ok".utf8), HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
            }
        )

        let requests = (0..<4).map { _ in Task { try await connection.data(from: URL(string: "/health")!) } }
        try await Task.sleep(nanoseconds: 50_000_000)
        await gate.open()
        for request in requests {
            _ = try await request.value
        }

        XCTAssertEqual(network.urls.count, 1)
        XCTAssertEqual(attempts.values.count, 1, "A shared verification is one attempt.")
    }

    func testDiscoveryReportsEachRouterThatItTries() async throws {
        let attempts = Recorder<Attempt>()
        let network = FakeNetwork { url, _ in
            switch url.host {
            case "atc.tinfoil.sh": return #"["router-a.example","router-b.example"]"#
            case "router-a.example": return FakeNetwork.document("reject", for: url)
            default: return FakeNetwork.document("ok", for: url)
            }
        }

        let client = try await RouterHTTPClient(verifying: EnclaveConnection.router(
            attestor: Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0, shuffle: { $0 }),
            transportMode: .tls,
            baseURL: nil,
            userCacheSecret: "test-secret",
            onVerification: { attempts.record(($0, $1)) }
        ))

        XCTAssertEqual(client.enclave, "router-b.example")
        XCTAssertEqual(attempts.values.map(\.host), ["router-a.example", "router-b.example"])
        XCTAssertNotNil(attempts.values.first?.result.error?.verificationError, "The skipped router is reported with its failure.")
        let last = await client.lastVerification
        XCTAssertNotNil(last?.report, "lastVerification describes the chosen router.")
        XCTAssertEqual(last?.report, attempts.values.last?.result.report)
    }

    func testTheFallbackRouterIsReportedWithItsHost() async throws {
        let attempts = Recorder<Attempt>()
        let network = FakeNetwork { url, _ in
            if url == TinfoilConstants.routerListURL {
                throw TinfoilError.network("unavailable")
            }
            return FakeNetwork.document("ok", for: url)
        }

        _ = try await RouterHTTPClient(verifying: EnclaveConnection.router(
            attestor: Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0),
            transportMode: .tls,
            baseURL: nil,
            userCacheSecret: "test-secret",
            onVerification: { attempts.record(($0, $1)) }
        ))

        XCTAssertEqual(attempts.values.map(\.host), [TinfoilConstants.fallbackEnclave])
    }

    func testEachGatewayReplicaKeepsItsOwnLastAttempt() async throws {
        let attempts = Recorder<Attempt>()
        let network = FakeNetwork { url, _ in
            FakeNetwork.document(url.host == "a.example" ? "reject" : "ok", for: url)
        }
        let base = URL(string: "https://gw.example/v1/")!
        let attestor = Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0)
        let router = GatewayRouter(
            baseURL: base,
            policy: try GatewayPolicy(pins: [:], pinnedOnly: false, attestor: attestor),
            catalog: {
                [
                    "m1": CatalogEntry(repo: "tinfoilsh/model-repo", hosts: ["a.example"]),
                    "m2": CatalogEntry(repo: "tinfoilsh/model-repo", hosts: ["b.example"]),
                ]
            },
            secret: "",
            makeReplica: { replica, attestor in
                try EnclaveConnection(
                    handle: EnclaveHandle(
                        enclave: replica.host,
                        pin: GatewayCatalog.pin(replica.reference),
                        attestationRelay: nil,
                        attestor: attestor,
                        onVerification: { attempts.record(($0, $1)) }
                    ),
                    transportMode: .ehbp,
                    baseURL: base,
                    userCacheSecret: ""
                )
            }
        )

        _ = try? await router.ensureVerified(model: "m1")
        let verified = try await router.ensureVerified(model: "m2")

        let entries = await router.lastVerification
        XCTAssertEqual(entries.map(\.host), ["a.example", "b.example"])
        XCTAssertNotNil(entries.first?.lastVerification.error?.verificationError, "The failed replica keeps its failure and report.")
        XCTAssertEqual(entries.last?.lastVerification.report, verified)
        XCTAssertEqual(Set(attempts.values.map(\.host)), ["a.example", "b.example"], "Each attempt names its replica.")
    }

    func testAnEHBPAttemptWithoutAnHPKEKeyFails() async throws {
        let attempts = Recorder<Attempt>()
        let handle = EnclaveHandle(
            enclave: "enclave.example",
            pin: Pin(repo: "org/repo"),
            attestationRelay: nil,
            attestor: Attestor(verifier: FakeVerifier(), fetch: { try self.serving("tls-only").fetch($0) }, retryDelay: 0),
            onVerification: { attempts.record(($0, $1)) },
            requiresHPKEKey: true
        )

        _ = try? await handle.ensureVerified()

        let last = await handle.lastVerification
        XCTAssertNil(last?.report, "A document that EHBP can't seal to is not a successful attempt.")
        XCTAssertTrue(last?.error?.message.contains("HPKE") ?? false, String(describing: last))
        XCTAssertEqual(attempts.values.last?.result.error, last?.error)
        let usable = await handle.usable
        XCTAssertNil(usable)
    }

    func testTheVerificationCheckSeesOnlyVerifiedFacts() async throws {
        let checked = Recorder<VerifiedFacts>()
        let connection = try connection(serving("reject", "reject", "ok"), verificationCheck: { checked.record($0) })

        _ = try? await connection.ensureUsable()
        XCTAssertTrue(checked.values.isEmpty, "The check is not called for a failed verification.")

        let report = try await connection.ensureUsable()
        XCTAssertEqual(checked.values, [try XCTUnwrap(report.verifiedFacts)])
    }

    func testTheCallbackCanCallTheClient() async throws {
        let holder = Holder<EnclaveConnection>()
        let seen = Recorder<(reported: Result<VerificationReport, TinfoilError>, last: Result<VerificationReport, TinfoilError>?)>()
        let connection = try connection(serving("ok", "reject"), onVerification: { _, result in
            // Blocks this callback until the client answers: it would never
            // answer if the callback ran on the client's actor.
            let answered = DispatchSemaphore(value: 0)
            let last = Holder<Result<VerificationReport, TinfoilError>>()
            Task {
                last.value = await holder.value?.lastVerification
                answered.signal()
            }
            XCTAssertEqual(answered.wait(timeout: .now() + 5), .success, "The callback's call to the client deadlocked.")
            seen.record((result, last.value))
        })
        holder.value = connection

        _ = try await connection.ensureUsable()
        _ = try? await connection.reverify()

        XCTAssertEqual(seen.values.count, 3)
        for (reported, last) in seen.values {
            XCTAssertNotNil(last, "The callback sees the attempt that it was called for, or a later one.")
            // A retried attempt is reported once its retry is done, so the
            // callback may see the later attempt.
            if reported.report != nil {
                XCTAssertEqual(last?.report, reported.report)
            } else {
                XCTAssertNotNil(last?.error)
            }
        }
    }

    func testAReturnedReportIsTheCallersCopy() async throws {
        let client = try await EnclaveHTTPClient(verifying: connection(serving("ok")))
        let report = try await client.ensureVerified()

        // A report is a value with immutable fields, so a caller can only
        // change a copy that it builds, here by editing its JSON form.
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any])
        var facts = try XCTUnwrap(object["verifiedFacts"] as? [String: Any])
        facts["tlsPublicKeyFingerprint"] = "00"
        object["verifiedFacts"] = facts
        let altered = try JSONDecoder().decode(VerificationReport.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertNotEqual(altered, report)

        let last = await client.lastVerification
        XCTAssertEqual(last?.report, report)
        let again = try await client.ensureVerified()
        XCTAssertEqual(again, report, "The client's state is unchanged.")
    }
}

/// A value set once a test has built what its closures need
private final class Holder<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: Value?

    var value: Value? {
        get { lock.withLock { _value } }
        set { lock.withLock { _value = newValue } }
    }
}
