import XCTest
import Foundation
@testable import Tinfoil

/// How EnclaveHTTPClient and RouterHTTPClient pick and verify their enclave
/// and check their configuration, using the stand-ins from
/// AttestationTestDoubles.swift in place of the network and Go.
final class EnclaveHTTPClientTests: XCTestCase {
    private func attestor(_ network: FakeNetwork) -> Attestor {
        Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0)
    }

    private func connection(
        _ network: FakeNetwork,
        transportMode: TransportMode = .tls,
        baseURL: URL? = nil
    ) throws -> EnclaveConnection {
        try EnclaveConnection(
            handle: EnclaveHandle(enclave: "enclave.example", repo: "org/repo", attestationRelay: nil, attestor: attestor(network)),
            transportMode: transportMode,
            baseURL: baseURL,
            userCacheSecret: ""
        )
    }

    private func router(
        _ network: FakeNetwork,
        transportMode: TransportMode = .ehbp,
        baseURL: URL? = nil,
        relay: String? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) async throws -> RouterHTTPClient {
        try await RouterHTTPClient(verifying: EnclaveConnection.router(
            attestor: attestor(network),
            transportMode: transportMode,
            baseURL: baseURL,
            attestationRelay: relay,
            userCacheSecret: "pinned so the tests never touch the persisted secret",
            onVerificationResult: onVerificationResult
        ))
    }

    private func approving(_ verdict: String = "ok") -> FakeNetwork {
        FakeNetwork { url, _ in
            url == TinfoilConstants.routerListURL ? #"["router-a.example"]"# : FakeNetwork.document(verdict, for: url)
        }
    }

    private func assertConfigurationError(_ body: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            guard case TinfoilError.configurationError = error else {
                return XCTFail("expected a configuration error, got \(error)", file: file, line: line)
            }
        }
    }

    func testAnEnclaveClientIsVerifiedBeforeItIsReturned() async throws {
        let network = approving()

        let client = try await EnclaveHTTPClient(verifying: connection(network))

        XCTAssertEqual(client.enclave, "enclave.example")
        XCTAssertEqual(client.repo, "org/repo")
        XCTAssertEqual(client.transportMode, .tls, "A named enclave uses pinned TLS by default.")
        XCTAssertEqual(network.urls.map(\.host), ["enclave.example"])
        let current = await client.current
        XCTAssertNotNil(current)
        _ = try await client.ensureVerified()
        XCTAssertEqual(network.urls.count, 1, "The verification made at creation is reused.")
    }

    func testAnEnclaveThatFailsVerificationFailsCreation() async {
        let network = approving("reject")
        do {
            _ = try await EnclaveHTTPClient(verifying: connection(network))
            XCTFail("a client must not be returned for an enclave that fails verification")
        } catch TinfoilError.attestationError {
        } catch {
            XCTFail("expected an attestation error, got \(error)")
        }
    }

    func testEHBPNeedsAnEnclaveThatEndorsesAnHPKEKey() async throws {
        do {
            _ = try await EnclaveHTTPClient(verifying: connection(approving("tls-only"), transportMode: .ehbp))
            XCTFail("EHBP must not be offered by an enclave without an HPKE key")
        } catch TinfoilError.attestationError(let failure) {
            XCTAssertTrue(failure.message.contains("HPKE"), failure.message)
        }
        _ = try await EnclaveHTTPClient(verifying: connection(approving("tls-only")))
    }

    func testARouterIsPickedAndVerifiedBeforeItIsReturned() async throws {
        let network = approving()
        let results = Recorder<Result<Verification, TinfoilError>>()

        let client = try await router(network, onVerificationResult: { results.record($0) })

        XCTAssertEqual(client.enclave, "router-a.example")
        XCTAssertEqual(client.repo, TinfoilConstants.defaultGithubRepo)
        XCTAssertEqual(client.transportMode, .ehbp, "A router uses EHBP by default.")
        let discovered = await client.current
        guard results.values.count == 1, case .success(let reported) = results.values[0] else {
            return XCTFail("expected discovery's verification to be reported once, got \(results.values)")
        }
        XCTAssertEqual(reported, discovered)

        XCTAssertNotNil(discovered, "Discovery's verification is kept.")
        let verified = try await client.ensureVerified()
        XCTAssertEqual(verified, discovered, "A fresh discovered verification is reused.")
        _ = try await client.reverify()
        XCTAssertEqual(
            network.urls.map(\.host),
            ["atc.tinfoil.sh", "router-a.example", "router-a.example"],
            "Later verifications stay with the router."
        )
    }

    func testTheFallbackRouterIsVerifiedBeforeItIsReturned() async throws {
        let network = FakeNetwork { url, previous in
            if url == TinfoilConstants.routerListURL {
                throw TinfoilError.network("unavailable")
            }
            return FakeNetwork.document(previous == 0 ? "reject" : "ok", for: url)
        }

        let client = try await router(network)

        XCTAssertEqual(client.enclave, TinfoilConstants.fallbackEnclave)
        let current = await client.current
        XCTAssertNotNil(current)
        XCTAssertEqual(
            network.urls.filter { $0.host == TinfoilConstants.fallbackEnclave }.count,
            2,
            "The fallback's verification is retried once."
        )
    }

    func testARelayIsAskedForTheFallbackRouterWithoutDiscovery() async throws {
        let network = approving()

        let client = try await router(network, relay: "relay.example")

        XCTAssertEqual(client.enclave, TinfoilConstants.fallbackEnclave)
        let url = try XCTUnwrap(network.urls.first)
        XCTAssertEqual(network.urls.count, 1, "A relay does not run discovery.")
        XCTAssertEqual(url.host, "relay.example")
        XCTAssertTrue(url.query?.contains("enclave=\(TinfoilConstants.fallbackEnclave)") ?? false)
    }

    func testARoutersBaseURLIsCheckedBeforeDiscovery() async {
        let cases: [(TransportMode, String)] = [
            (.tls, "https://proxy.example/"),  // needs EHBP: the router's origin isn't known
            (.ehbp, "http://proxy.example/"),
            (.ehbp, "https://user:secret@proxy.example/"),
            (.ehbp, "https:proxy.example/"),
        ]
        for (mode, url) in cases {
            let network = approving()
            do {
                _ = try await router(network, transportMode: mode, baseURL: URL(string: url)!)
                XCTFail("\(url) must be refused")
            } catch TinfoilError.configurationError {
            } catch {
                XCTFail("expected a configuration error for \(url), got \(error)")
            }
            XCTAssertTrue(network.urls.isEmpty, "\(url) is refused before discovery.")
        }
    }

    func testBaseURLRulesAreCheckedBeforeAnyNetworkIO() throws {
        let network = approving()
        let proxy = URL(string: "https://proxy.example/api/")!
        assertConfigurationError({ try self.connection(network, baseURL: proxy) })
        let proxied = try connection(network, transportMode: .ehbp, baseURL: proxy)
        XCTAssertEqual(proxied.baseURL, proxy, "EHBP keeps bodies sealed through a proxy.")
        XCTAssertEqual(proxied.enclave, "enclave.example", "The enclave stays the one verified.")
        let path = try connection(network, baseURL: URL(string: "https://enclave.example/v1/")!)
        XCTAssertEqual(path.baseURL.absoluteString, "https://enclave.example/v1/", "TLS accepts a path on the enclave's own origin.")
        assertConfigurationError({ try self.connection(network, transportMode: .ehbp, baseURL: URL(string: "http://proxy.example/")!) })
        XCTAssertTrue(network.urls.isEmpty)
    }

    func testOpenAIClientsRequireEHBP() async throws {
        let tls = try await EnclaveHTTPClient(verifying: connection(approving()))
        XCTAssertThrowsError(try EnclaveOpenAIClient(httpClient: tls, apiKey: "test-key")) { error in
            guard case TinfoilError.configurationError = error else {
                return XCTFail("expected a configuration error, got \(error)")
            }
        }
        let ehbp = try await EnclaveHTTPClient(verifying: connection(approving(), transportMode: .ehbp))
        let client = try EnclaveOpenAIClient(httpClient: ehbp, apiKey: "test-key")
        XCTAssertTrue(client.httpClient === ehbp)
    }

    func testAMissingAPIKeyFailsBeforeAnyNetworkIO() async throws {
        guard ProcessInfo.processInfo.environment["TINFOIL_API_KEY"] == nil else {
            throw XCTSkip("TINFOIL_API_KEY is set in the environment")
        }
        do {
            // An unreachable enclave would fail with a network error.
            _ = try await EnclaveOpenAIClient(enclave: "127.0.0.1:9", repo: "org/repo")
            XCTFail("a client without an API key must not be created")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains("TINFOIL_API_KEY"), failure.message)
        }
    }

    func testEHBPRequestsGoOnlyToTheBaseURLsOrigin() async throws {
        let network = approving()
        let client = try connection(network, transportMode: .ehbp, baseURL: URL(string: "https://proxy.example/")!)

        do {
            _ = try await client.data(from: URL(string: "https://elsewhere.example/v1/models")!)
            XCTFail("a request to another origin must be refused")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains("elsewhere.example"), failure.message)
        }
        XCTAssertTrue(network.urls.isEmpty, "A refused request does not verify.")
    }

    /// The EHBP key starts unknown and is taken from the handle: a
    /// verification made first, as a client's initializer makes one, is reused
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
        XCTAssertEqual(first.endpoint.publicKey, Data(hexString: try XCTUnwrap(verified.hpkePublicKey)), "Sealed to the verified HPKE key")
        XCTAssertEqual(first.endpoint.expiresAt, verified.freshnessExpiresAt)
        XCTAssertEqual(network.urls.count, 1, "The handle's verification is reused for the first request.")

        let refreshed = try await channel.state.refresh(afterRejectedGeneration: first.generation)
        XCTAssertEqual(network.urls.count, 2, "A rejected key is verified again.")
        XCTAssertNotEqual(refreshed.expiresAt, first.endpoint.expiresAt)
    }
}
