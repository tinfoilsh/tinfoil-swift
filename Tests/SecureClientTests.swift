import XCTest
import Foundation
@testable import TinfoilAI

/// How SecureClient picks the enclave to verify, using the stand-ins from
/// AttestationTestDoubles.swift in place of the network and Go.
final class SecureClientTests: XCTestCase {
    private func client(
        enclave: String? = nil,
        repo: String = TinfoilConstants.defaultGithubRepo,
        relay: String? = nil,
        network: FakeNetwork
    ) throws -> SecureClient {
        try SecureClient(
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
        XCTAssertThrowsError(try SecureClient(repo: "org/repo")) { error in
            guard case TinfoilError.invalidConfiguration = error else {
                return XCTFail("expected a configuration error, got \(error)")
            }
        }
        XCTAssertNoThrow(try SecureClient(enclave: "enclave.example", repo: "org/repo"))
    }

    func testVerifiesTheConfiguredEnclave() async throws {
        let network = approving()
        let client = try client(enclave: "enclave.example", repo: "org/repo", network: network)

        let verification = try await client.verify()

        XCTAssertEqual(verification.enclaveHost, "enclave.example")
        XCTAssertEqual(network.urls.map(\.host), ["enclave.example"], "A configured enclave is never discovered.")
        let latest = await client.verification
        XCTAssertEqual(latest, verification)
    }

    func testDiscoveryPicksARouterOnceAndStaysWithIt() async throws {
        let network = approving()
        let client = try client(network: network)

        let first = try await client.verify()
        let second = try await client.verify()

        XCTAssertEqual(first.enclaveHost, "router-a.example")
        XCTAssertEqual(second.enclaveHost, "router-a.example")
        XCTAssertEqual(network.urls.map(\.host), ["atc.tinfoil.sh", "router-a.example", "router-a.example"])
    }

    func testRelayWithoutAnEnclaveAttestsTheFallbackRouter() async throws {
        let network = approving()
        let client = try client(relay: "relay.example", network: network)

        let verification = try await client.verify()

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
        let client = try client(enclave: "enclave.example", network: network)
        let first = try await client.verify()

        do {
            _ = try await client.verify()
            XCTFail("a rejected attestation must fail verification")
        } catch TinfoilError.attestationError {
        }

        let latest = await client.verification
        XCTAssertEqual(latest, first)
    }
}
