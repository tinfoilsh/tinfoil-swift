import XCTest
import Foundation
@testable import TinfoilAI

final class AttestorTests: XCTestCase {
    private let routerList = TinfoilConstants.routerListURL

    /// - Parameter hanging: Hosts whose fetches are recorded and then never
    ///   answer, until they are cancelled.
    private func attestor(
        _ verifier: FakeVerifier,
        _ network: FakeNetwork,
        retryDelay: TimeInterval = 0,
        hanging: Set<String> = [],
        discoveryTimeout: TimeInterval = 30,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
        onEnclaveVerified: EnclaveVerifiedCallback? = nil
    ) -> Attestor {
        Attestor(
            verifier: verifier,
            fetch: { url in
                let reply = try network.fetch(url)
                if hanging.contains(url.host ?? "") {
                    try await Task.sleep(nanoseconds: 60_000_000_000)
                }
                return reply
            },
            retryDelay: retryDelay,
            discoveryTimeout: discoveryTimeout,
            now: now,
            onEnclaveVerified: onEnclaveVerified
        )
    }

    private func assertThrows<T>(
        _ body: () async throws -> T,
        _ check: (Error) -> Bool,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await body()
            XCTFail("expected an error", file: file, line: line)
        } catch {
            XCTAssertTrue(check(error), "unexpected error \(error)", file: file, line: line)
        }
    }

    func testAttestsHost() async throws {
        let network = FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) }

        let verification = try await attestor(FakeVerifier(), network)
            .attest(host: "enclave.example", relay: nil, repo: "org/repo")

        XCTAssertEqual(verification.enclaveHost, "enclave.example")
        XCTAssertEqual(network.urls.map(\.host), ["enclave.example"])
    }

    func testFetchesThroughRelay() async throws {
        let network = FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) }

        let verification = try await attestor(FakeVerifier(), network)
            .attest(host: "enclave.example", relay: "relay.example", repo: "org/repo")

        XCTAssertEqual(verification.enclaveHost, "enclave.example", "The verification records the enclave, not the relay.")
        let url = try XCTUnwrap(network.urls.first)
        XCTAssertEqual(url.host, "relay.example")
        XCTAssertTrue(url.query?.contains("enclave=enclave.example") ?? false)
    }

    func testRetriesOnceWithAFreshNonce() async throws {
        let network = FakeNetwork { url, previous in
            if previous == 0 { throw TinfoilError.networkError("unavailable") }
            return FakeNetwork.document("ok", for: url)
        }

        _ = try await attestor(FakeVerifier(), network).attest(host: "enclave.example", relay: nil, repo: "org/repo")

        XCTAssertEqual(network.urls.count, 2)
        XCTAssertNotEqual(network.urls[0], network.urls[1], "Each attempt fetches with its own nonce.")
    }

    func testGivesUpAfterTheRetry() async {
        let network = FakeNetwork { url, _ in FakeNetwork.document("reject", for: url) }

        await assertThrows(
            { try await self.attestor(FakeVerifier(), network).attest(host: "enclave.example", relay: nil, repo: "org/repo") },
            { $0 as? TinfoilError == .attestationError("rejected") }
        )
        XCTAssertEqual(network.urls.count, 2)
    }

    func testDoesNotRetryAConfigurationError() async {
        let network = FakeNetwork { url, _ in FakeNetwork.document("config", for: url) }

        await assertThrows(
            { try await self.attestor(FakeVerifier(), network).attest(host: "enclave.example", relay: nil, repo: "org/repo") },
            { $0 as? TinfoilError == .configurationError("bad repo") }
        )
        XCTAssertEqual(network.urls.count, 1)
    }

    func testCancellationDuringTheRetryDelay() async {
        let network = FakeNetwork { _, _ in throw TinfoilError.networkError("unavailable") }
        let attestor = attestor(FakeVerifier(), network, retryDelay: 60)
        let attempt = Task { try await attestor.attest(host: "enclave.example", relay: nil, repo: "org/repo") }
        try? await Task.sleep(nanoseconds: 100_000_000)
        attempt.cancel()

        await assertThrows({ try await attempt.value }, { $0 is CancellationError })
        XCTAssertEqual(network.urls.count, 1)
    }

    func testDiscoveryPicksTheFirstRouterThatVerifies() async throws {
        let verifier = FakeVerifier()
        let network = FakeNetwork { url, _ in
            switch url.host {
            case "atc.tinfoil.sh": return #"["router-a.example","router-b.example"]"#
            case "router-a.example": return FakeNetwork.document("reject", for: url)
            default: return FakeNetwork.document("ok", for: url)
            }
        }

        let verification = try await attestor(verifier, network).attestDefaultRouter()

        XCTAssertEqual(verification.enclaveHost, "router-b.example")
        XCTAssertEqual(
            network.urls.map(\.host),
            ["atc.tinfoil.sh", "router-a.example", "router-b.example"],
            "Each discovered router is tried once, without a retry."
        )
        XCTAssertEqual(Set(verifier.repos), [TinfoilConstants.defaultGithubRepo])
    }

    func testDiscoveryFallsBackWhenNoRouterVerifies() async throws {
        let network = FakeNetwork { url, _ in
            switch url.host {
            case "atc.tinfoil.sh": return #"["router-a.example"]"#
            case "router-a.example": return FakeNetwork.document("reject", for: url)
            default: return FakeNetwork.document("ok", for: url)
            }
        }

        let verification = try await attestor(FakeVerifier(), network).attestDefaultRouter()

        XCTAssertEqual(verification.enclaveHost, TinfoilConstants.fallbackEnclave)
    }

    func testDiscoveryFallsBackWithoutARouterList() async throws {
        for listReply in [{ () throws -> String in throw TinfoilError.networkError("unavailable") }, { "not json" }] {
            let network = FakeNetwork { url, _ in
                url == self.routerList ? try listReply() : FakeNetwork.document("ok", for: url)
            }

            let verification = try await attestor(FakeVerifier(), network).attestDefaultRouter()

            XCTAssertEqual(verification.enclaveHost, TinfoilConstants.fallbackEnclave)
        }
    }

    func testDiscoveryFallsBackAtTheDeadline() async throws {
        let network = FakeNetwork { url, _ in
            url == self.routerList ? #"["router-a.example","router-b.example"]"# : FakeNetwork.document("ok", for: url)
        }
        let started = Date()

        let verification = try await attestor(FakeVerifier(), network, hanging: ["router-a.example"], discoveryTimeout: 0.2)
            .attestDefaultRouter()

        XCTAssertEqual(verification.enclaveHost, TinfoilConstants.fallbackEnclave)
        XCTAssertEqual(
            network.urls.map(\.host),
            ["atc.tinfoil.sh", "router-a.example", TinfoilConstants.fallbackEnclave],
            "The deadline ends the probe in flight and skips the routers left."
        )
        XCTAssertLessThan(Date().timeIntervalSince(started), 10)
    }

    func testDiscoveryDeadlineCoversTheRouterList() async throws {
        let network = FakeNetwork { url, _ in
            url == self.routerList ? #"["router-a.example"]"# : FakeNetwork.document("ok", for: url)
        }

        let verification = try await attestor(FakeVerifier(), network, hanging: ["atc.tinfoil.sh"], discoveryTimeout: 0.2)
            .attestDefaultRouter()

        XCTAssertEqual(verification.enclaveHost, TinfoilConstants.fallbackEnclave)
        XCTAssertEqual(network.urls.map(\.host), ["atc.tinfoil.sh", TinfoilConstants.fallbackEnclave])
    }

    func testDiscoveryStopsAtTheDeadlineBeforeTheTimerFires() async throws {
        let network = FakeNetwork { url, _ in
            switch url.host {
            case "atc.tinfoil.sh": return #"["router-a.example","router-b.example"]"#
            case "router-a.example": return FakeNetwork.document("reject", for: url)
            default: return FakeNetwork.document("ok", for: url)
            }
        }
        // The clock passes the deadline once router-a has been tried, long
        // before the 30 second timer could cancel discovery.
        let started = ContinuousClock.now
        let now: @Sendable () -> ContinuousClock.Instant = {
            network.urls.contains { $0.host == "router-a.example" } ? started.advanced(by: .seconds(31)) : started
        }

        let verification = try await attestor(FakeVerifier(), network, now: now).attestDefaultRouter()

        XCTAssertEqual(verification.enclaveHost, TinfoilConstants.fallbackEnclave)
        XCTAssertFalse(network.urls.contains { $0.host == "router-b.example" }, "No router is tried past the deadline.")
    }

    func testCancellingDiscovery() async {
        let network = FakeNetwork { url, _ in
            url == self.routerList ? #"["router-a.example"]"# : FakeNetwork.document("ok", for: url)
        }
        let attestor = attestor(FakeVerifier(), network, hanging: ["router-a.example"])
        let discovery = Task { try await attestor.attestDefaultRouter() }
        try? await Task.sleep(nanoseconds: 100_000_000)
        discovery.cancel()

        await assertThrows({ try await discovery.value }, { $0 is CancellationError })
        XCTAssertFalse(network.urls.contains { $0.host == TinfoilConstants.fallbackEnclave }, "A cancelled discovery does not fall back.")
    }

    func testDiscoveryRetriesTheFallback() async throws {
        let network = FakeNetwork { url, previous in
            switch url.host {
            case "atc.tinfoil.sh": return "[]"
            default: return FakeNetwork.document(previous == 0 ? "reject" : "ok", for: url)
            }
        }

        let verification = try await attestor(FakeVerifier(), network).attestDefaultRouter()

        XCTAssertEqual(verification.enclaveHost, TinfoilConstants.fallbackEnclave)
        XCTAssertEqual(network.urls.filter { $0.host == TinfoilConstants.fallbackEnclave }.count, 2)
    }

    func testOnEnclaveVerifiedSeesEachVerifiedEnclaveOnce() async throws {
        let verified = Recorder<String>()
        let network = FakeNetwork { url, previous in
            FakeNetwork.document(previous == 0 ? "reject" : "ok", for: url)
        }

        _ = try await attestor(FakeVerifier(), network, onEnclaveVerified: { verified.record($0.enclaveHost) })
            .attest(host: "enclave.example", relay: nil, repo: "org/repo")

        XCTAssertEqual(verified.values, ["enclave.example"], "A failed attempt is never passed to the callback.")
    }

    func testARejectedEnclaveIsNotRetried() async {
        let network = FakeNetwork { url, _ in FakeNetwork.document("ok", for: url) }

        await assertThrows(
            {
                try await self.attestor(FakeVerifier(), network, onEnclaveVerified: { _ in throw Refusal() })
                    .attest(host: "enclave.example", relay: nil, repo: "org/repo")
            },
            { error in
                guard case TinfoilError.attestationError(let message, _) = error else { return false }
                return message.contains("enclave.example") && message.contains("refused by the test")
            }
        )
        XCTAssertEqual(network.urls.count, 1)
    }

    func testDiscoveryPassesOverARejectedRouter() async throws {
        let network = FakeNetwork { url, _ in
            url.host == "atc.tinfoil.sh"
                ? #"["router-a.example","router-b.example"]"#
                : FakeNetwork.document("ok", for: url)
        }
        let onEnclaveVerified: EnclaveVerifiedCallback = { verification in
            if verification.enclaveHost == "router-a.example" {
                throw Refusal()
            }
        }

        let verification = try await attestor(FakeVerifier(), network, onEnclaveVerified: onEnclaveVerified).attestDefaultRouter()

        XCTAssertEqual(verification.enclaveHost, "router-b.example")
    }
}
