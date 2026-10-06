import XCTest
import Foundation
@testable import TinfoilAI

final class AttestorTests: XCTestCase {
    private let routerList = TinfoilConstants.routerListURL

    private func attestor(
        _ verifier: FakeVerifier,
        _ network: FakeNetwork,
        retryDelay: TimeInterval = 0
    ) -> Attestor {
        Attestor(verifier: verifier, fetch: { try network.fetch($0) }, retryDelay: retryDelay)
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
            if previous == 0 { throw TinfoilError.fetchError("unavailable") }
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
            { $0 as? TinfoilError == .invalidConfiguration("bad repo") }
        )
        XCTAssertEqual(network.urls.count, 1)
    }

    func testCancellationDuringTheRetryDelay() async {
        let network = FakeNetwork { _, _ in throw TinfoilError.fetchError("unavailable") }
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
        for listReply in [{ () throws -> String in throw TinfoilError.fetchError("unavailable") }, { "not json" }] {
            let network = FakeNetwork { url, _ in
                url == self.routerList ? try listReply() : FakeNetwork.document("ok", for: url)
            }

            let verification = try await attestor(FakeVerifier(), network).attestDefaultRouter()

            XCTAssertEqual(verification.enclaveHost, TinfoilConstants.fallbackEnclave)
        }
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
}
