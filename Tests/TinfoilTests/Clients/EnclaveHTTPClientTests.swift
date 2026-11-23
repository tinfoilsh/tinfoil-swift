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
            handle: EnclaveHandle(enclave: "enclave.example", pin: Pin(repo: "org/repo"), attestationRelay: nil, attestor: attestor(network)),
            transportMode: transportMode,
            baseURL: baseURL,
            userCacheSecret: ""
        )
    }

    private func router(
        _ network: FakeNetwork,
        transportMode: TransportMode = .ehbp,
        baseURL: URL? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) async throws -> RouterHTTPClient {
        try await RouterHTTPClient(verifying: EnclaveConnection.router(
            attestor: attestor(network),
            transportMode: transportMode,
            baseURL: baseURL,
            userCacheSecret: "test-secret",
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
        XCTAssertEqual(client.trust.repo, "org/repo")
        XCTAssertEqual(client.transport, .tls, "A named enclave uses pinned TLS by default.")
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
        XCTAssertEqual(client.connection.pin, TinfoilConstants.routerPin)
        XCTAssertEqual(client.transport, .ehbp(), "The test helper selects EHBP.")
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

    func testARoutersBaseURLIsCheckedBeforeDiscovery() async {
        let cases: [(TransportMode, String)] = [
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
        let proxied = try connection(network, transportMode: .ehbp, baseURL: proxy)
        XCTAssertEqual(proxied.baseURL, proxy, "EHBP keeps bodies sealed through a proxy.")
        XCTAssertEqual(proxied.enclave, "enclave.example", "The enclave stays the one verified.")
        assertConfigurationError({ try self.connection(network, transportMode: .ehbp, baseURL: URL(string: "http://proxy.example/")!) })
        let refusals = ["https://proxy.example/api/?", "https://proxy.example/api/?key=secret", "https://proxy.example/api/#", "https://enclave.example/v1#x", "https://enclave.example/v1?key=secret"]
        for mode in [TransportMode.tls, .ehbp] { for refused in refusals {
            XCTAssertThrowsError(try connection(network, transportMode: mode, baseURL: URL(string: refused)!)) { error in
                guard case TinfoilError.configurationError(let failure) = error else {
                    return XCTFail("expected a configuration error, got \(error)")
                }
                // The exact message holds no part of the URL, whose query may
                // hold a secret.
                XCTAssertEqual(failure.message, "invalid base URL: a base URL must not carry a query or a fragment")
            }
        } }
        XCTAssertTrue(network.urls.isEmpty)
    }

    /// HTTP base URLs that EHBP accepts: the host as written is localhost or
    /// a loopback IP address.
    private static let loopbackHTTPBaseURLs = [
        "http://localhost:8080/v1",
        "http://LOCALHOST/v1",
        "HTTP://localhost/v1",
        "http://127.0.0.1:8080/v1",
        "http://127.1.2.3/v1",
        "http://127.255.255.254/v1",
        "http://[::1]:8080/v1",
        "http://[0:0:0:0:0:0:0:1]/v1",
        "http://[::ffff:127.0.0.1]/v1",
        "http://[::ffff:7f00:1]/v1",
        "http://[::1%25lo0]/v1",
    ]

    /// Base URLs every mode refuses, most of them HTTP off loopback. Names
    /// aren't resolved, and IPv4 must be four decimal octets without leading
    /// zeros, since a resolver may read other forms differently.
    private static let refusedBaseURLs = [
        "http://proxy.example/v1",
        "http://app.localhost/v1",
        "http://localhost.example/v1",
        "http://localhost./v1",
        "http://%6cocalhost/v1",
        "http://0.0.0.0:8080/v1",
        "http://10.0.0.1/v1",
        "http://128.0.0.1/v1",
        "http://127.0.0.1./v1",
        "http://127.1/v1",
        "http://0127.0.0.1/v1",
        "http://127.0.0.01/v1",
        "http://0x7f.0.0.1/v1",
        "http://2130706433/v1",
        "http://[::]/v1",
        "http://[::2]/v1",
        "http://[::127.0.0.1]/v1",
        "http://[::ffff:10.0.0.1]/v1",
        "http://[::ffff:127.0.0.01]/v1",
        "http://user:secret@localhost/v1",
        "ftp://localhost/v1",
        "/v1",
        // A query or a fragment, even an empty one, in any mode.
        "http://localhost/v1?",
        "http://localhost/v1?key=secret",
        "http://localhost/v1#",
        "http://localhost/v1#part",
    ]

    func testEHBPAcceptsAnHTTPBaseURLOnlyOnALoopbackHost() throws {
        let network = approving()
        for url in Self.loopbackHTTPBaseURLs + ["https://proxy.example/v1"] {
            let connection = try connection(network, transportMode: .ehbp, baseURL: URL(string: url)!)
            XCTAssertEqual(connection.baseURL.absoluteString, url)
        }
        for url in Self.refusedBaseURLs {
            assertConfigurationError({ try self.connection(network, transportMode: .ehbp, baseURL: URL(string: url)!) })
        }
        XCTAssertTrue(network.urls.isEmpty)
    }

    func testTLSRefusesAnHTTPBaseURLOnLoopback() throws {
        let network = approving()
        for url in Self.loopbackHTTPBaseURLs {
            assertConfigurationError({ try self.connection(network, baseURL: URL(string: url)!) })
        }
        // Not even on the enclave's own host, which TLS reaches over HTTPS.
        assertConfigurationError({
            try EnclaveConnection(
                handle: EnclaveHandle(enclave: "localhost:8080", pin: Pin(repo: "org/repo"), attestationRelay: nil, attestor: self.attestor(network)),
                transportMode: .tls,
                baseURL: URL(string: "http://localhost:8080/v1")!,
                userCacheSecret: ""
            )
        })
        XCTAssertTrue(network.urls.isEmpty)
    }

    /// The public initializers check the proxy URL before any network I/O:
    /// the enclave and the router's relay are unreachable, so reaching them
    /// would fail with a network error instead.
    func testThePublicInitializersRefuseAnHTTPProxyURLOffLoopback() async throws {
        for url in Self.refusedBaseURLs {
            let transport = Transport.ehbp(proxyURL: URL(string: url)!)
            do {
                _ = try await EnclaveHTTPClient(enclave: "127.0.0.1:9", trust: .repo("org/repo"), options: .init(transport: transport))
                XCTFail("\(url) must be refused")
            } catch TinfoilError.configurationError(let failure) {
                if url.hasPrefix("http://"), !url.contains("@"), !url.contains("?"), !url.contains("#") {
                    XCTAssertTrue(failure.message.contains("loopback"), failure.message)
                }
            }
            do {
                _ = try await RouterHTTPClient(options: .init(
                    transport: transport,
                    fetchAttestation: AttestationFetcher { _, _ in throw TinfoilError.network("no network in this test") },
                    fetchRouterList: RouterListFetcher { XCTFail("discovery ran despite a refused proxy URL"); return [] }
                ))
                XCTFail("\(url) must be refused")
            } catch TinfoilError.configurationError {
            }
        }
    }

    /// A proxy URL on the enclave's own origin is no proxy, and is refused
    /// before any network I/O, with or without the default port.
    func testAProxyURLOnTheEnclavesOwnOriginIsRefused() async throws {
        for url in ["https://127.0.0.1:9/relay", "https://enclave.example:443", "https://ENCLAVE.example/relay/"] {
            let enclave = url.contains("127.0.0.1") ? "127.0.0.1:9" : "enclave.example"
            do {
                _ = try await EnclaveHTTPClient(
                    enclave: enclave,
                    trust: .repo("org/repo"),
                    options: .init(transport: .ehbp(proxyURL: URL(string: url)!))
                )
                XCTFail("\(url) must be refused")
            } catch TinfoilError.configurationError(let failure) {
                XCTAssertTrue(failure.message.contains("the enclave's own origin"), failure.message)
            }
        }
    }

    func testTheTransportsAreValues() {
        let proxy = URL(string: "https://proxy.example/relay")!
        XCTAssertNil(Transport.tls.proxyURL)
        XCTAssertNil(Transport.ehbp().proxyURL)
        XCTAssertEqual(Transport.ehbp(proxyURL: proxy).proxyURL, proxy)
        XCTAssertNotEqual(Transport.tls, Transport.ehbp())
        XCTAssertEqual(EnclaveOptions().transport, .tls, "TLS is the default.")
        XCTAssertEqual(RouterOptions().transport, .tls, "TLS is the default.")
    }

    func testARouterAcceptsAnHTTPBaseURLOnLoopback() async throws {
        let network = approving()
        let client = try await router(network, baseURL: URL(string: "http://localhost:8080/v1/")!)
        XCTAssertEqual(client.baseURL.absoluteString, "http://localhost:8080/v1/")
        XCTAssertEqual(client.enclave, "router-a.example", "The router verified stays the enclave.")

        let verifications = network.urls.count
        for target in ["https://localhost:8080/v1/models", "http://localhost:8081/v1/models", "http://127.0.0.1:8080/v1/models", "http://router-a.example/v1/models"] {
            do {
                _ = try await client.data(from: URL(string: target)!)
                XCTFail("\(target) must be refused")
            } catch TinfoilError.configurationError {
            }
        }
        XCTAssertEqual(network.urls.count, verifications, "A refused request does not verify.")
    }

    func testOpenAIClientsUseTheHTTPClientsTransport() async throws {
        for mode in [TransportMode.tls, .ehbp] {
            let httpClient = try await EnclaveHTTPClient(verifying: connection(approving(), transportMode: mode))
            let client = try OpenAIClient(httpClient: httpClient, apiKey: "test-key")
            XCTAssertTrue(client.httpClient === httpClient)
            XCTAssertEqual(httpClient.transport.mode, mode)
        }
    }

    func testAMissingAPIKeyFailsBeforeAnyNetworkIO() async throws {
        do {
            // The router's discovery would fail with a network error.
            _ = try await OpenAIClient()
            XCTFail("a client without an API key must not be created")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains("pass apiKey or apiKeyProvider"), failure.message)
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
        let handle = EnclaveHandle(enclave: "enclave.example", pin: Pin(repo: "org/repo"), attestationRelay: nil, attestor: attestor(network))
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

    /// A handle and the EHBP channel over it, verified, whose attestation
    /// source serves verdict, failing as a network error does while it is
    /// "offline"
    private func verifiedChannel(_ verdict: Verdict) async throws -> (FakeNetwork, EnclaveHandle, EHBPChannel) {
        let network = FakeNetwork { url, _ in
            if verdict.value == "offline" {
                throw TinfoilError.network("attestation source unreachable")
            }
            return FakeNetwork.document(verdict.value, for: url)
        }
        let handle = EnclaveHandle(enclave: "enclave.example", pin: Pin(repo: "org/repo"), attestationRelay: nil, attestor: attestor(network))
        let channel = EHBPChannel(
            origin: "https://enclave.example",
            enclaveURL: "https://enclave.example",
            handle: handle,
            initial: nil,
            userCacheSecret: ""
        )
        _ = try await channel.state.current()
        return (network, handle, channel)
    }

    func testAFailedReverifyStopsSealingToTheDiscardedKey() async throws {
        let verdict = Verdict("ok")
        let (network, handle, channel) = try await verifiedChannel(verdict)
        let first = try await channel.state.current().endpoint.verification

        verdict.value = "reject"
        do {
            _ = try await handle.reverify()
            XCTFail("a rejected attestation must fail the re-verification")
        } catch TinfoilError.attestationError {
        }
        let fetched = network.urls.count
        do {
            _ = try await channel.state.current()
            XCTFail("no request may be sealed to the discarded key")
        } catch TinfoilError.attestationError {
        }
        XCTAssertGreaterThan(network.urls.count, fetched, "The next request verified the enclave again.")

        verdict.value = "ok"
        let recovered = try await channel.state.current().endpoint.verification
        let current = await handle.current
        XCTAssertNotNil(recovered)
        XCTAssertNotEqual(recovered, first)
        XCTAssertEqual(recovered, current, "Requests are sealed under the new verification.")
    }

    /// The path that a gateway replica takes when the enclave rejects its key
    func testAFailedRecoveryFromARejectedEHBPKeyStopsSealing() async throws {
        let verdict = Verdict("ok")
        let (network, handle, channel) = try await verifiedChannel(verdict)
        let sealing = try await channel.state.current()

        verdict.value = "reject"
        do {
            _ = try await channel.state.refresh(afterRejectedGeneration: sealing.generation)
            XCTFail("the recovery must fail while the enclave fails verification")
        } catch TinfoilError.attestationError {
        }
        let discarded = await handle.current
        XCTAssertNil(discarded)
        let fetched = network.urls.count
        do {
            _ = try await channel.state.current()
            XCTFail("no request may be sealed to the rejected key")
        } catch TinfoilError.attestationError {
        }
        XCTAssertGreaterThan(network.urls.count, fetched)

        verdict.value = "ok"
        let recovered = try await channel.state.current()
        XCTAssertNotEqual(recovered.endpoint.verification, sealing.endpoint.verification)
    }

    func testAReverifyThatCannotReachTheAttestationSourceKeepsTheEHBPKey() async throws {
        let verdict = Verdict("ok")
        let (network, handle, channel) = try await verifiedChannel(verdict)
        let sealing = try await channel.state.current()

        verdict.value = "offline"
        do {
            _ = try await handle.reverify()
            XCTFail("an unreachable attestation source must fail the re-verification")
        } catch TinfoilError.networkError {
        }
        let fetched = network.urls.count
        let current = try await channel.state.current()

        XCTAssertEqual(current.generation, sealing.generation)
        XCTAssertEqual(current.endpoint.verification, sealing.endpoint.verification)
        XCTAssertEqual(network.urls.count, fetched, "No new verification was needed.")
    }

    func testASuccessfulReverifyReplacesTheEHBPKeyWithoutVerifyingAgain() async throws {
        let verdict = Verdict("ok")
        let (network, handle, channel) = try await verifiedChannel(verdict)
        let sealing = try await channel.state.current()

        let newer = try await handle.reverify()
        let fetched = network.urls.count
        let current = try await channel.state.current()

        XCTAssertNotEqual(current.endpoint.verification, sealing.endpoint.verification)
        XCTAssertEqual(current.endpoint.verification, newer)
        XCTAssertEqual(network.urls.count, fetched)
    }

    func testAFailedRouterReverifyVerifiesTheSameRouterAgain() async throws {
        let verdict = Verdict("ok")
        let network = FakeNetwork { url, _ in
            url == TinfoilConstants.routerListURL ? #"["router-a.example"]"# : FakeNetwork.document(verdict.value, for: url)
        }
        let client = try await router(network)

        verdict.value = "reject"
        do {
            _ = try await client.reverify()
            XCTFail("a rejected attestation must fail the re-verification")
        } catch TinfoilError.attestationError {
        }
        let discarded = await client.current
        XCTAssertNil(discarded)

        verdict.value = "ok"
        _ = try await client.ensureVerified()
        XCTAssertEqual(network.urls.filter { $0 == TinfoilConstants.routerListURL }.count, 1, "Discovery doesn't run again.")
        XCTAssertEqual(Set(network.urls.compactMap(\.host)), ["atc.tinfoil.sh", "router-a.example"])
    }
}
