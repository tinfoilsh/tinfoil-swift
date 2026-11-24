import XCTest
import Foundation
@testable import Tinfoil

/// The gateway's `reverify(model:)` and its replicas' current verifications,
/// over replicas that verify through real handles against the stand-in
/// verifier.
final class GatewayReverifyTests: XCTestCase {
    /// A gateway that serves model "m" from two replicas, first and second in
    /// the model's order. Each replica's documents are served by verdict for
    /// its host, "ok" unless a test changes it.
    final class Gateway: @unchecked Sendable {
        let hosts = ["a.example", "b.example"]
        let first: String
        let second: String
        let clock = ManualClock()
        private let lock = NSLock()
        private var _verdicts: [String: String] = [:]
        private var _fetches: [String: Int] = [:]
        private(set) var router: GatewayRouter!

        init() throws {
            let order = GatewayRouter.rank(hosts, prefix: "m", first: "")
            first = order[0]
            second = order[1]
            let base = URL(string: "https://gw.example/")!
            let clock = self.clock
            let attestor = Attestor(verifier: FakeVerifier(now: { clock.now }), fetch: { url in
                try self.serve(url)
            }, retryDelay: 0)
            router = GatewayRouter(
                baseURL: base,
                policy: try GatewayPolicy(pins: ["m": ("tinfoilsh/model-repo", nil)], attestor: attestor),
                catalog: { ["m": CatalogEntry(repo: "tinfoilsh/model-repo", hosts: self.hosts)] },
                secret: "",
                makeReplica: { replica, attestor in
                    try EnclaveConnection(
                        handle: EnclaveHandle(
                            enclave: replica.host,
                            pin: GatewayCatalog.pin(replica.reference),
                            attestationRelay: nil,
                            attestor: attestor,
                            requiresHPKEKey: true,
                            now: { clock.now }
                        ),
                        transportMode: .ehbp,
                        baseURL: base,
                        userCacheSecret: ""
                    )
                }
            )
        }

        func setVerdict(_ verdict: String, for host: String) {
            lock.withLock { _verdicts[host] = verdict }
        }

        func fetches(of host: String) -> Int {
            lock.withLock { _fetches[host] ?? 0 }
        }

        private func serve(_ url: URL) throws -> Data {
            let host = url.host ?? ""
            let verdict = lock.withLock {
                _fetches[host, default: 0] += 1
                return _verdicts[host] ?? "ok"
            }
            if verdict == "offline" {
                throw TinfoilError.network("attestation source unreachable")
            }
            return Data(FakeNetwork.document(verdict, for: url).utf8)
        }

        func entry(_ host: String) async throws -> ReplicaVerification {
            let entries = await router.replicaVerifications
            return try XCTUnwrap(entries.first { $0.host == host }, "no entry for \(host)")
        }
    }

    func testReverifyVerifiesTheReplicaInUseAgain() async throws {
        let gateway = try Gateway()
        let ensured = try await gateway.router.ensureVerified(model: "m")

        let reverified = try await gateway.router.reverify(model: "m")
        XCTAssertNotEqual(reverified, ensured, "The valid verification is verified again.")
        XCTAssertEqual(gateway.fetches(of: gateway.first), 2)
        XCTAssertEqual(gateway.fetches(of: gateway.second), 0, "No other replica is verified.")

        let entry = try await gateway.entry(gateway.first)
        XCTAssertEqual(entry.current, reverified)
        XCTAssertEqual(entry.lastAttempt.report, reverified)
        let entries = await gateway.router.replicaVerifications
        XCTAssertEqual(entries.count, 1)
        let again = try await gateway.router.ensureVerified(model: "m")
        XCTAssertEqual(again, reverified)
    }

    /// A failure that keeps the replica's verification is the outcome:
    /// requests for the model still go to that replica.
    func testReverifyReportsAFailureThatKeepsTheVerification() async throws {
        let gateway = try Gateway()
        let ensured = try await gateway.router.ensureVerified(model: "m")
        gateway.setVerdict("offline", for: gateway.first)

        do {
            _ = try await gateway.router.reverify(model: "m")
            XCTFail("the replica's network failure should be reverify's outcome")
        } catch TinfoilError.networkError {
        }
        XCTAssertEqual(gateway.fetches(of: gateway.second), 0, "The next replica is not tried.")

        let entry = try await gateway.entry(gateway.first)
        XCTAssertEqual(entry.current, ensured, "The replica's verification is still current.")
        guard case .networkError? = entry.lastAttempt.error else {
            return XCTFail("the last attempt should be the failure, got \(entry.lastAttempt)")
        }
        let again = try await gateway.router.ensureVerified(model: "m")
        XCTAssertEqual(again, ensured)
    }

    /// An attestation failure discards the replica's verification, so
    /// reverify moves on to the replica that ensureVerified then returns.
    func testReverifyMovesOnAfterADiscard() async throws {
        let gateway = try Gateway()
        _ = try await gateway.router.ensureVerified(model: "m")
        gateway.setVerdict("reject", for: gateway.first)

        let reverified = try await gateway.router.reverify(model: "m")
        XCTAssertEqual(reverified.verifiedFacts?.configRepo, "tinfoilsh/model-repo")
        XCTAssertGreaterThan(gateway.fetches(of: gateway.second), 0)

        let discarded = try await gateway.entry(gateway.first)
        XCTAssertNil(discarded.current, "The failure discarded the replica's verification.")
        guard case .attestationError? = discarded.lastAttempt.error else {
            return XCTFail("the last attempt should be the attestation failure, got \(discarded.lastAttempt)")
        }
        let next = try await gateway.entry(gateway.second)
        XCTAssertEqual(next.current, reverified)
        XCTAssertEqual(next.lastAttempt.report, reverified)

        let fetches = gateway.fetches(of: gateway.first)
        let again = try await gateway.router.ensureVerified(model: "m")
        XCTAssertEqual(again, reverified, "ensureVerified returns the same replica")
        XCTAssertGreaterThan(gateway.fetches(of: gateway.first), fetches, "after it tries the first replica again.")
    }

    func testReverifyRefusesAnUnpinnedModel() async throws {
        let gateway = try Gateway()
        do {
            _ = try await gateway.router.reverify(model: "unpinned")
            XCTFail("an unpinned model must be refused")
        } catch TinfoilError.configurationError {
        }
        let entries = await gateway.router.replicaVerifications
        XCTAssertTrue(entries.isEmpty, "No replica is verified.")
    }

    func testAReplicasCurrentVerificationExpires() async throws {
        let gateway = try Gateway()
        let ensured = try await gateway.router.ensureVerified(model: "m")
        gateway.clock.advance(by: 2 * 3600)

        let entry = try await gateway.entry(gateway.first)
        XCTAssertNil(entry.current, "An expired verification is not current.")
        XCTAssertEqual(entry.lastAttempt.report, ensured)
    }
}
