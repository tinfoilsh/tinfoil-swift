import XCTest
import Foundation
@testable import TinfoilAI

/// How EnclaveHTTPClient picks its enclave and checks its configuration,
/// using the stand-ins from AttestationTestDoubles.swift in place of the
/// network and Go.
final class EnclaveHTTPClientTests: XCTestCase {
    private func attestor(_ network: FakeNetwork) -> Attestor {
        Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0)
    }

    private func discover(
        _ network: FakeNetwork,
        transportMode: TransportMode = .ehbp,
        baseURL: URL? = nil,
        relay: String? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) async throws -> EnclaveHTTPClient {
        try await EnclaveHTTPClient.discoverRouter(
            attestor: attestor(network),
            transportMode: transportMode,
            baseURL: baseURL,
            attestationRelay: relay,
            userCacheSecret: "pinned so the tests never touch the persisted secret",
            onVerificationResult: onVerificationResult
        )
    }

    private func approving() -> FakeNetwork {
        FakeNetwork { url, _ in
            url == TinfoilConstants.routerListURL ? #"["router-a.example"]"# : FakeNetwork.document("ok", for: url)
        }
    }

    private func assertConfigurationError(_ body: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            guard case TinfoilError.configurationError = error else {
                return XCTFail("expected a configuration error, got \(error)", file: file, line: line)
            }
        }
    }

    func testCreatingAClientDoesNoNetworkIO() async throws {
        let client = try EnclaveHTTPClient(enclave: "enclave.example", repo: "org/repo")

        XCTAssertEqual(client.enclave, "enclave.example")
        XCTAssertEqual(client.repo, "org/repo")
        XCTAssertEqual(client.transportMode, .tls, "A named enclave uses pinned TLS by default, as in Go.")
        let current = await client.current
        XCTAssertNil(current)
    }

    func testDiscoveryPicksARouterAndStaysWithIt() async throws {
        let network = approving()
        let results = Recorder<Result<Verification, TinfoilError>>()

        let client = try await discover(network, onVerificationResult: { results.record($0) })

        XCTAssertEqual(client.enclave, "router-a.example")
        XCTAssertEqual(client.repo, TinfoilConstants.defaultGithubRepo)
        XCTAssertEqual(client.transportMode, .ehbp, "Discovery uses EHBP by default, as in Go.")
        let discovered = await client.current
        XCTAssertEqual(discovered?.enclaveHost, "router-a.example", "Discovery's verification is kept.")
        guard results.values.count == 1, case .success(let reported) = results.values[0] else {
            return XCTFail("expected discovery's verification to be reported once, got \(results.values)")
        }
        XCTAssertEqual(reported, discovered)

        let verified = try await client.ensureVerified()
        XCTAssertEqual(verified, discovered, "A fresh discovered verification is reused.")
        let reverified = try await client.reverify()
        XCTAssertEqual(reverified.enclaveHost, "router-a.example", "Later verifications stay with the router.")
        XCTAssertEqual(network.urls.map(\.host), ["atc.tinfoil.sh", "router-a.example", "router-a.example"])
    }

    func testDiscoveryFallsBackAndVerifiesTheFallbackOnFirstUse() async throws {
        let network = FakeNetwork { url, previous in
            if url == TinfoilConstants.routerListURL {
                throw TinfoilError.network("unavailable")
            }
            return FakeNetwork.document(previous == 0 ? "reject" : "ok", for: url)
        }

        let client = try await discover(network)

        XCTAssertEqual(client.enclave, TinfoilConstants.fallbackEnclave)
        XCTAssertEqual(network.urls.map(\.host), ["atc.tinfoil.sh"], "The fallback is verified on first use, not by discovery.")
        let verified = try await client.ensureVerified()
        XCTAssertEqual(verified.enclaveHost, TinfoilConstants.fallbackEnclave)
        XCTAssertEqual(
            network.urls.filter { $0.host == TinfoilConstants.fallbackEnclave }.count,
            2,
            "The fallback's verification is retried once."
        )
    }

    func testARelayIsAskedForTheFallbackRouterWithoutDiscovery() async throws {
        let network = approving()

        let client = try await discover(network, relay: "relay.example")

        XCTAssertEqual(client.enclave, TinfoilConstants.fallbackEnclave)
        XCTAssertTrue(network.urls.isEmpty, "A relay does not run discovery.")
        _ = try await client.ensureVerified()
        let url = try XCTUnwrap(network.urls.first)
        XCTAssertEqual(network.urls.count, 1)
        XCTAssertEqual(url.host, "relay.example")
        XCTAssertTrue(url.query?.contains("enclave=\(TinfoilConstants.fallbackEnclave)") ?? false)
    }

    func testDiscoveryWithABaseURLRequiresEHBP() async {
        let network = approving()
        do {
            _ = try await discover(network, transportMode: .tls, baseURL: URL(string: "https://proxy.example/")!)
            XCTFail("a base URL needs EHBP when the router's origin isn't known")
        } catch TinfoilError.configurationError {
        } catch {
            XCTFail("expected a configuration error, got \(error)")
        }
        XCTAssertTrue(network.urls.isEmpty, "The configuration is checked before discovery.")
    }

    func testBaseURLRules() throws {
        let proxy = URL(string: "https://proxy.example/api/")!
        assertConfigurationError({
            try EnclaveHTTPClient(enclave: "enclave.example", repo: "org/repo", baseURL: proxy)
        })
        let proxied = try EnclaveHTTPClient(enclave: "enclave.example", repo: "org/repo", transportMode: .ehbp, baseURL: proxy)
        XCTAssertEqual(proxied.baseURL, proxy, "EHBP keeps bodies sealed through a proxy.")
        XCTAssertEqual(proxied.enclave, "enclave.example", "The enclave stays the one verified.")
        let path = try EnclaveHTTPClient(enclave: "enclave.example", repo: "org/repo", baseURL: URL(string: "https://enclave.example/v1/")!)
        XCTAssertEqual(path.baseURL.absoluteString, "https://enclave.example/v1/", "TLS accepts a path on the enclave's own origin.")
        assertConfigurationError({
            try EnclaveHTTPClient(enclave: "enclave.example", repo: "org/repo", transportMode: .ehbp, baseURL: URL(string: "http://proxy.example/")!)
        })
    }

    func testEHBPRequestsGoOnlyToTheBaseURLsOrigin() async throws {
        let network = approving()
        let client = try EnclaveHTTPClient(
            handle: EnclaveHandle(enclave: "enclave.example", repo: "org/repo", attestationRelay: nil, attestor: attestor(network)),
            transportMode: .ehbp,
            baseURL: URL(string: "https://proxy.example/")!,
            userCacheSecret: ""
        )

        do {
            _ = try await client.data(from: URL(string: "https://elsewhere.example/v1/models")!)
            XCTFail("a request to another origin must be refused")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains("elsewhere.example"), failure.message)
        }
        XCTAssertTrue(network.urls.isEmpty, "A refused request does not verify.")
    }

    /// The EHBP key starts unknown and is taken from the handle: a
    /// verification made first, as TinfoilAI.create makes one, is reused
    /// rather than attesting again, while a rejected key verifies again.
    func testTheEHBPKeyComesFromTheHandle() async throws {
        let network = approving()
        let handle = EnclaveHandle(enclave: "enclave.example", repo: "org/repo", attestationRelay: nil, attestor: attestor(network))
        let channel = EHBPChannel(
            origin: "https://enclave.example",
            enclaveURL: "https://enclave.example",
            handle: handle,
            initial: nil,
            userCacheSecret: ""
        )

        let verified = try await handle.ensureVerified()
        let first = try await channel.state.current()
        XCTAssertEqual(first.endpoint.expiresAt, verified.freshnessExpiresAt)
        XCTAssertEqual(network.urls.count, 1, "The handle's verification is reused for the first request.")

        let refreshed = try await channel.state.refresh(afterRejectedGeneration: first.generation)
        XCTAssertEqual(network.urls.count, 2, "A rejected key is verified again.")
        XCTAssertNotEqual(refreshed.expiresAt, first.endpoint.expiresAt)
    }
}
