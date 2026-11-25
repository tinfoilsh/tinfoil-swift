import XCTest
import Foundation
@testable import Tinfoil

/// Every report that a client hands out names the host that the client
/// contacted in `metadata.host`, on each path that hands one out, while the
/// verifier's own report names none.
final class ReportHostTests: XCTestCase {
    private typealias Attempt = (host: String, result: Result<VerificationReport, TinfoilError>)

    /// The `metadata.host` of report's JSON form, or nil
    private func jsonHost(_ report: VerificationReport?, file: StaticString = #filePath, line: UInt = #line) throws -> String? {
        let report = try XCTUnwrap(report, "no report", file: file, line: line)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any], file: file, line: line)
        let metadata = try XCTUnwrap(object["metadata"] as? [String: Any], file: file, line: line)
        return metadata["host"] as? String
    }

    private func handle(
        _ verdict: Verdict,
        onVerificationAttempt: VerificationCallback? = nil
    ) -> EnclaveHandle {
        let network = FakeNetwork { url, _ in FakeNetwork.document(verdict.value, for: url) }
        return EnclaveHandle(
            enclave: "enclave.example",
            pin: Pin(repo: "org/repo"),
            attestationRelay: nil,
            attestor: Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0),
            onVerificationAttempt: onVerificationAttempt,
            requiresHPKEKey: true
        )
    }

    func testTheVerifiersOwnReportNamesNoHost() throws {
        let verifier = FakeVerifier()
        let nonce = verifier.newNonce()
        let report = try verifier.verify(document: Data("ok:\(nonce.hexString)".utf8), nonce: nonce, pin: Pin(repo: "org/repo"))
        XCTAssertNil(report.metadata.host)
        XCTAssertNil(try jsonHost(report))
    }

    /// An enclave client names its enclave, even through an EHBP proxy, on
    /// every path: ensure, reverify, current, the last attempt and the
    /// callback.
    func testAnEnclaveClientNamesItsEnclaveOnEveryPath() async throws {
        let attempts = Recorder<Attempt>()
        let client = try await EnclaveHTTPClient(verifying: EnclaveConnection(
            handle: handle(Verdict("ok"), onVerificationAttempt: { attempts.record(($0, $1)) }),
            transportMode: .ehbp,
            baseURL: URL(string: "https://proxy.example/relay/")!,
            userCacheSecret: ""
        ))

        let ensured = try await client.ensureVerified()
        XCTAssertEqual(try jsonHost(ensured), "enclave.example", "ensureVerified")
        let reverified = try await client.reverify()
        XCTAssertEqual(try jsonHost(reverified), "enclave.example", "reverify")
        let current = await client.currentVerification
        XCTAssertEqual(try jsonHost(current), "enclave.example", "currentVerification")
        let last = await client.lastVerificationAttempt
        XCTAssertEqual(try jsonHost(last?.report), "enclave.example", "lastVerificationAttempt")
        XCTAssertFalse(attempts.values.isEmpty)
        for attempt in attempts.values {
            XCTAssertEqual(try jsonHost(attempt.result.report), "enclave.example", "onVerificationAttempt")
        }
    }

    /// A rejection's report names the host too, wherever the error reaches
    /// the caller.
    func testARejectionsReportNamesTheHost() async throws {
        let attempts = Recorder<Attempt>()
        let handle = handle(Verdict("reject"), onVerificationAttempt: { attempts.record(($0, $1)) })
        do {
            _ = try await handle.ensureVerified()
            XCTFail("a rejected document must fail verification")
        } catch let error as TinfoilError {
            XCTAssertEqual(try jsonHost(error.verificationError?.report), "enclave.example", "thrown")
        }
        let last = await handle.lastVerificationAttempt
        XCTAssertEqual(try jsonHost(last?.error?.verificationError?.report), "enclave.example", "lastVerificationAttempt")
        XCTAssertEqual(attempts.values.count, 2)
        for attempt in attempts.values {
            XCTAssertEqual(try jsonHost(attempt.result.error?.verificationError?.report), "enclave.example", "onVerificationAttempt")
        }
    }

    /// Router discovery names each router that it tries, rejected or chosen.
    func testDiscoveryNamesEachRouter() async throws {
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
            onVerificationAttempt: { attempts.record(($0, $1)) }
        ))

        let reported = attempts.values
        XCTAssertEqual(reported.map(\.host), ["router-a.example", "router-b.example"])
        XCTAssertEqual(try jsonHost(reported[0].result.error?.verificationError?.report), "router-a.example")
        XCTAssertEqual(try jsonHost(reported[1].result.report), "router-b.example")
        let current = await client.currentVerification
        XCTAssertEqual(try jsonHost(current), "router-b.example")
        let ensured = try await client.ensureVerified()
        XCTAssertEqual(try jsonHost(ensured), "router-b.example")
    }

    /// A gateway client names each replica, in its entries and from
    /// ensureVerified(model:), including a replica that failed.
    func testAGatewayClientNamesEachReplica() async throws {
        // The replica that the model's order tries first rejects, so that
        // both replicas are tried.
        let hosts = ["a.example", "b.example"]
        let order = GatewayRouter.rank(hosts, prefix: "m", first: "")
        let network = FakeNetwork { url, _ in
            FakeNetwork.document(url.host == order[0] ? "reject" : "ok", for: url)
        }
        let base = URL(string: "https://gw.example/")!
        let attestor = Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0)
        let router = GatewayRouter(
            baseURL: base,
            policy: try GatewayPolicy(pins: ["m": ("tinfoilsh/model-repo", nil)], attestor: attestor),
            catalog: { ["m": CatalogEntry(repo: "tinfoilsh/model-repo", hosts: hosts)] },
            secret: "",
            makeReplica: { replica, attestor in
                try EnclaveConnection(
                    handle: EnclaveHandle(enclave: replica.host, pin: GatewayCatalog.pin(replica.reference), attestationRelay: nil, attestor: attestor, requiresHPKEKey: true),
                    transportMode: .ehbp,
                    baseURL: base,
                    userCacheSecret: ""
                )
            }
        )

        let ensured = try await router.ensureVerified(model: "m")
        XCTAssertEqual(try jsonHost(ensured), order[1])
        let verified = try await router.reverify(model: "m")
        XCTAssertEqual(try jsonHost(verified), order[1])
        let entries = await router.replicaVerifications
        XCTAssertEqual(entries.map(\.host), hosts, "Both replicas were tried.")
        XCTAssertNotNil(entries.first { $0.host == order[0] }?.lastAttempt.error?.verificationError, "The first replica was rejected.")
        for entry in entries {
            switch entry.lastAttempt {
            case .success(let report):
                XCTAssertEqual(try jsonHost(report), entry.host)
                XCTAssertEqual(try jsonHost(entry.current), entry.host)
            case .failure(let error):
                XCTAssertEqual(try jsonHost(error.verificationError?.report), entry.host)
            }
        }
    }
}
