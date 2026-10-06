import XCTest
import Foundation
@testable import TinfoilAI

/// How EnclaveHandle picks the enclave to verify, using the stand-ins from
/// AttestationTestDoubles.swift in place of the network and Go.
final class EnclaveHandleTests: XCTestCase {
    private func handle(
        enclave: String? = nil,
        repo: String = TinfoilConstants.defaultGithubRepo,
        relay: String? = nil,
        network: FakeNetwork
    ) throws -> EnclaveHandle {
        try EnclaveHandle(
            enclave: enclave,
            repo: repo,
            attestationRelay: relay,
            attestor: Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0)
        )
    }

    private func approving() -> FakeNetwork {
        FakeNetwork { url, _ in
            url.host == "atc.tinfoil.sh" ? #"["router-a.example"]"# : FakeNetwork.document("ok", for: url)
        }
    }

    func testCustomRepoRequiresAnEnclave() {
        let network = approving()
        XCTAssertThrowsError(try handle(repo: "org/repo", network: network)) { error in
            guard case TinfoilError.invalidConfiguration = error else {
                return XCTFail("expected a configuration error, got \(error)")
            }
        }
        XCTAssertNoThrow(try handle(enclave: "enclave.example", repo: "org/repo", network: network))
        XCTAssertTrue(network.urls.isEmpty)
    }

    func testVerifiesTheConfiguredEnclave() async throws {
        let network = approving()
        let handle = try handle(enclave: "enclave.example", repo: "org/repo", network: network)

        let verification = try await handle.verify()

        XCTAssertEqual(verification.enclaveHost, "enclave.example")
        XCTAssertEqual(network.urls.map(\.host), ["enclave.example"], "A configured enclave is never discovered.")
        let latest = await handle.verification
        XCTAssertEqual(latest, verification)
    }

    func testDiscoveryPicksARouterOnceAndStaysWithIt() async throws {
        let network = approving()
        let handle = try handle(network: network)

        let first = try await handle.verify()
        let second = try await handle.verify()

        XCTAssertEqual(first.enclaveHost, "router-a.example")
        XCTAssertEqual(second.enclaveHost, "router-a.example")
        XCTAssertEqual(network.urls.map(\.host), ["atc.tinfoil.sh", "router-a.example", "router-a.example"])
    }

    func testRelayWithoutAnEnclaveAttestsTheFallbackRouter() async throws {
        let network = approving()
        let handle = try handle(relay: "relay.example", network: network)

        let verification = try await handle.verify()

        XCTAssertEqual(verification.enclaveHost, TinfoilConstants.fallbackEnclave)
        let url = try XCTUnwrap(network.urls.first)
        XCTAssertEqual(network.urls.count, 1, "A relay does not run discovery.")
        XCTAssertEqual(url.host, "relay.example")
        XCTAssertTrue(url.query?.contains("enclave=\(TinfoilConstants.fallbackEnclave)") ?? false)
    }

    func testFailedVerificationKeepsTheLastResult() async throws {
        let network = FakeNetwork { url, previous in
            FakeNetwork.document(previous == 0 ? "ok" : "reject", for: url)
        }
        let handle = try handle(enclave: "enclave.example", network: network)
        let first = try await handle.verify()

        do {
            _ = try await handle.verify()
            XCTFail("a rejected attestation must fail verification")
        } catch TinfoilError.attestationError {
        }

        let latest = await handle.verification
        XCTAssertEqual(latest, first)
    }

    /// A handle whose router list fetch waits on gate, reporting each
    /// discovery it starts. A fetch checks for cancellation once it resumes,
    /// so a cancelled verification fails rather than finishing unnoticed.
    private func gatedHandle(
        gate: AsyncGate,
        discoveries: DiscoveryCounter
    ) throws -> EnclaveHandle {
        let network = approving()
        let fetch: Attestor.Fetch = { url in
            if url == TinfoilConstants.routerListURL {
                discoveries.started()
                await gate.wait()
                try Task.checkCancellation()
            }
            return try network.fetch(url)
        }
        return try EnclaveHandle(
            enclave: nil,
            repo: TinfoilConstants.defaultGithubRepo,
            attestationRelay: nil,
            attestor: Attestor(verifier: FakeVerifier(), fetch: fetch, retryDelay: 0)
        )
    }

    func testConcurrentFirstCallsShareOneDiscovery() async throws {
        let gate = AsyncGate()
        let discoveries = DiscoveryCounter(
            first: expectation(description: "discovery started"),
            more: expectation(description: "a second discovery")
        )
        let handle = try gatedHandle(gate: gate, discoveries: discoveries)

        let calls = (0..<3).map { _ in Task { try await handle.verify() } }
        await fulfillment(of: [discoveries.first], timeout: 1)
        // Inverted: passes only if no other call starts its own discovery
        // while the first is held.
        await fulfillment(of: [discoveries.more], timeout: 0.2)
        await gate.open()

        var hosts: Set<String> = []
        for call in calls {
            hosts.insert(try await call.value.enclaveHost)
        }
        XCTAssertEqual(hosts, ["router-a.example"])
        XCTAssertEqual(discoveries.count, 1)
    }

    func testCancellingOneCallLeavesTheSharedVerificationRunning() async throws {
        let gate = AsyncGate()
        let discoveries = DiscoveryCounter(
            first: expectation(description: "discovery started"),
            more: expectation(description: "a second discovery")
        )
        let handle = try gatedHandle(gate: gate, discoveries: discoveries)

        let cancelledReturned = expectation(description: "the cancelled call returned")
        let cancelled = Task {
            defer { cancelledReturned.fulfill() }
            return try await handle.verify()
        }
        await fulfillment(of: [discoveries.first], timeout: 1)
        let waiting = Task { try await handle.verify() }
        cancelled.cancel()
        // The cancelled call must return without waiting for the shared
        // verification, which stays held until the gate opens.
        await fulfillment(of: [cancelledReturned], timeout: 1)
        await gate.open()
        do {
            _ = try await cancelled.value
            XCTFail("the cancelled call must end with cancellation")
        } catch is CancellationError {
        }

        let verification = try await waiting.value
        XCTAssertEqual(verification.enclaveHost, "router-a.example")
        let latest = await handle.verification
        XCTAssertEqual(latest, verification)
        await fulfillment(of: [discoveries.more], timeout: 0.1)
        XCTAssertEqual(discoveries.count, 1)
    }
}

/// Counts router discoveries, fulfilling first on the first and more on any
/// after it, which tests invert to assert there is no second.
private final class DiscoveryCounter: @unchecked Sendable {
    let first: XCTestExpectation
    let more: XCTestExpectation
    private let lock = NSLock()
    private var _count = 0

    init(first: XCTestExpectation, more: XCTestExpectation) {
        self.first = first
        self.more = more
        more.isInverted = true
        // Without single-flight every caller discovers; let the inverted wait
        // report that rather than an over-fulfilled expectation.
        more.assertForOverFulfill = false
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return _count
    }

    func started() {
        lock.lock()
        _count += 1
        let count = _count
        lock.unlock()
        (count == 1 ? first : more).fulfill()
    }
}
