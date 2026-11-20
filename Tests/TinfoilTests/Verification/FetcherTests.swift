import XCTest
import Foundation
@testable import Tinfoil

/// The caller's choice of how attestation documents and the router list are
/// fetched: the relay protocol, URL checks before any I/O, where each
/// fetcher is used, and how its errors are reported.
final class FetcherTests: XCTestCase {
    private let nonce = Data((0..<32).map { UInt8($0) })
    private var nonceHex: String { nonce.map { String(format: "%02x", $0) }.joined() }

    /// Records the hosts that a fetcher was asked for, and answers with a
    /// document of `verdict` for each one's nonce.
    private final class Recorder: @unchecked Sendable {
        private let lock = NSLock()
        private var _hosts: [String] = []
        let verdict: @Sendable (String) -> String

        init(verdict: @escaping @Sendable (String) -> String = { _ in "ok" }) {
            self.verdict = verdict
        }

        var hosts: [String] {
            lock.lock()
            defer { lock.unlock() }
            return _hosts
        }

        var fetcher: AttestationFetcher {
            AttestationFetcher { host, nonce in
                self.lock.lock()
                self._hosts.append(host)
                self.lock.unlock()
                return Data("\(self.verdict(host)):\(nonce.hexString)".utf8)
            }
        }
    }

    /// A direct fetch, which these tests must not make
    private let noDirectFetch: Attestor.Fetch = { url in
        XCTFail("fetched \(url) directly")
        throw TinfoilError.network("no direct fetch in this test")
    }

    // MARK: - Relay protocol

    func testTheAttestationRelayURLJoinsUnderTheRelaysPath() throws {
        let url = { (relay: String, host: String) in
            try AttestationFetcher.relayAttestationURL(URL(string: relay)!, host: host, nonce: self.nonce).absoluteString
        }
        let suffix = "/.well-known/tinfoil-attestation?nonce=\(nonceHex)&enclave=enclave.example"
        XCTAssertEqual(try url("https://app.example/tinfoil", "enclave.example"), "https://app.example/tinfoil" + suffix)
        XCTAssertEqual(try url("https://app.example/tinfoil/", "enclave.example"), "https://app.example/tinfoil" + suffix)
        XCTAssertEqual(try url("https://app.example", "enclave.example"), "https://app.example" + suffix)
        XCTAssertEqual(try url("https://app.example/", "enclave.example"), "https://app.example" + suffix)
        XCTAssertEqual(try url("http://localhost:8080/tinfoil", "enclave.example"), "http://localhost:8080/tinfoil" + suffix)
        XCTAssertEqual(
            try url("https://app.example/tinfoil", "enclave.example:8443"),
            "https://app.example/tinfoil/.well-known/tinfoil-attestation?nonce=\(nonceHex)&enclave=enclave.example%3A8443"
        )
        XCTAssertEqual(nonceHex, nonceHex.lowercased())
    }

    func testTheRelaysGoThroughTheirGETs() async throws {
        let asked = Box<[URL]>(value: [])
        let attestation = AttestationFetcher.relay(URL(string: "https://app.example/tinfoil/")!) { url in
            asked.value.append(url)
            return Data("document".utf8)
        }
        let document = try await attestation(host: "enclave.example", nonce: nonce)
        XCTAssertEqual(document, Data("document".utf8), "The body is the document, unchanged.")

        let list = RouterListFetcher.relay(URL(string: "https://app.example/tinfoil")!) { url in
            asked.value.append(url)
            return Data(#"["router-a.example","router-b.example"]"#.utf8)
        }
        let routers = try await list.fetch()
        XCTAssertEqual(routers, ["router-a.example", "router-b.example"])
        let root = RouterListFetcher.relay(URL(string: "https://app.example")!) { url in
            asked.value.append(url)
            return Data("[]".utf8)
        }
        _ = try await root.fetch()
        XCTAssertEqual(asked.value.map(\.absoluteString), [
            "https://app.example/tinfoil/.well-known/tinfoil-attestation?nonce=\(nonceHex)&enclave=enclave.example",
            "https://app.example/tinfoil/routers",
            "https://app.example/routers",
        ])
    }

    func testARelayedRouterListIsParsedAsTinfoilsIs() async {
        for body in [#"{"routers":[]}"#, "[1,2]", "not json", #"["a",null]"#] {
            let list = RouterListFetcher.relay(URL(string: "https://app.example")!) { _ in Data(body.utf8) }
            do {
                _ = try await list.fetch()
                XCTFail("\(body) is not a router list")
            } catch TinfoilError.networkError {
            } catch {
                XCTFail("expected a network error for \(body), got \(error)")
            }
        }
    }

    /// A relay fetch is a direct fetch with its limits: HTTPS, or HTTP only to
    /// a loopback relay.
    func testARelayFetchIsHTTPSOrLoopbackHTTP() async {
        do {
            _ = try await DocumentFetcher().fetch(URL(string: "http://relay.example/routers")!, allowingLoopbackHTTP: true)
            XCTFail("plaintext to another host must be refused")
        } catch TinfoilError.configurationError {
        } catch {
            XCTFail("expected a configuration error, got \(error)")
        }
        do {
            // Nothing listens on port 9, so the fetch is made and fails.
            _ = try await DocumentFetcher(timeout: 2).fetch(URL(string: "http://127.0.0.1:9/routers")!, allowingLoopbackHTTP: true)
            XCTFail("nothing listens on port 9")
        } catch TinfoilError.networkError {
        } catch {
            XCTFail("expected a network error, got \(error)")
        }
    }

    // MARK: - URL checks before any I/O

    private static let refusedRelayURLs = [
        "http://relay.example/tinfoil",
        "http://app.localhost/tinfoil",
        "http://0.0.0.0:8080/tinfoil",
        "/tinfoil",
        "ftp://relay.example/tinfoil",
        "https://user:secret@relay.example/tinfoil",
        "https://relay.example/tinfoil?",
        "https://relay.example/tinfoil?x=1",
        "https://relay.example/tinfoil#",
    ]

    func testRelayURLsAreCheckedBeforeAnyNetworkIO() async {
        for url in Self.refusedRelayURLs {
            let relay = URL(string: url)!
            do {
                _ = try await EnclaveHTTPClient(enclave: "127.0.0.1:9", trust: .repo("org/repo"), options: .init(fetchAttestation: .relay(relay)))
                XCTFail("\(url) must be refused")
            } catch TinfoilError.configurationError(let failure) {
                XCTAssertTrue(failure.message.contains("invalid relay URL"), failure.message)
            } catch {
                XCTFail("expected a configuration error for \(url), got \(error)")
            }
            do {
                _ = try await RouterHTTPClient(options: .init(fetchAttestation: .relay(relay)))
                XCTFail("\(url) must be refused")
            } catch TinfoilError.configurationError {
            } catch {
                XCTFail("expected a configuration error for \(url), got \(error)")
            }
            do {
                _ = try await RouterHTTPClient(options: .init(
                    fetchAttestation: AttestationFetcher { _, _ in throw TinfoilError.network("no network in this test") },
                    fetchRouterList: .relay(relay)
                ))
                XCTFail("\(url) must be refused")
            } catch TinfoilError.configurationError {
            } catch {
                XCTFail("expected a configuration error for \(url), got \(error)")
            }
        }
        XCTAssertNoThrow(try EnclaveConnection.validateRelayURL(URL(string: "http://localhost:8080/tinfoil")!))
        XCTAssertNoThrow(try EnclaveConnection.validateRelayURL(URL(string: "https://app.example/tinfoil/")!))
    }

    // MARK: - Where the fetchers are used

    func testACallersAttestationFetcherServesEveryVerification() async throws {
        let recorder = Recorder()
        let attestor = Attestor(verifier: FakeVerifier(), fetch: noDirectFetch, retryDelay: 0, fetchAttestation: recorder.fetcher)
        let handle = EnclaveHandle(enclave: "enclave.example", pin: Pin(repo: "org/repo"), attestationRelay: nil, attestor: attestor)

        _ = try await handle.ensureVerified()
        _ = try await handle.reverify()

        XCTAssertEqual(recorder.hosts, ["enclave.example", "enclave.example"])
    }

    func testDiscoveryUsesBothFetchersAndTheFallback() async throws {
        // Each listed router is rejected, so the fallback serves.
        let recorder = Recorder { $0 == TinfoilConstants.fallbackEnclave ? "ok" : "reject" }
        let attestor = Attestor(
            verifier: FakeVerifier(),
            fetch: noDirectFetch,
            retryDelay: 0,
            fetchAttestation: recorder.fetcher,
            fetchRouterList: RouterListFetcher { ["router-a.example", "router-b.example"] },
            shuffle: { $0 }
        )

        let connection = try await EnclaveConnection.router(
            attestor: attestor,
            transportMode: .tls,
            baseURL: nil,
            userCacheSecret: "secret",
            onVerificationResult: nil
        )
        _ = try await connection.ensureVerified()

        XCTAssertEqual(connection.enclave, TinfoilConstants.fallbackEnclave)
        XCTAssertEqual(recorder.hosts, ["router-a.example", "router-b.example", TinfoilConstants.fallbackEnclave])
    }

    /// Discovery runs with an EHBP proxy and both relays: requests go to the
    /// proxy, and fetches to the relays.
    func testDiscoveryRunsWithAProxyAndBothRelays() async throws {
        let asked = Box<[URL]>(value: [])
        let relay = URL(string: "https://app.example/tinfoil")!
        let attestor = Attestor(
            verifier: FakeVerifier(),
            fetch: noDirectFetch,
            retryDelay: 0,
            fetchAttestation: .relay(relay) { url in
                asked.value.append(url)
                return Data(FakeNetwork.document("ok", for: url).utf8)
            },
            fetchRouterList: .relay(relay) { url in
                asked.value.append(url)
                return Data(#"["router-a.example"]"#.utf8)
            }
        )

        let connection = try await EnclaveConnection.router(
            attestor: attestor,
            transportMode: .ehbp,
            baseURL: URL(string: "https://app.example/tinfoil/proxy")!,
            userCacheSecret: "secret",
            onVerificationResult: nil
        )

        XCTAssertEqual(connection.enclave, "router-a.example")
        XCTAssertEqual(connection.baseURL.absoluteString, "https://app.example/tinfoil/proxy")
        XCTAssertEqual(asked.value.map(\.path), ["/tinfoil/routers", "/tinfoil/.well-known/tinfoil-attestation"])
    }

    func testAFailedRouterListFallsBackWithoutTinfoilsList() async throws {
        let recorder = Recorder()
        let attestor = Attestor(
            verifier: FakeVerifier(),
            fetch: noDirectFetch,
            retryDelay: 0,
            fetchAttestation: recorder.fetcher,
            fetchRouterList: RouterListFetcher { throw URLError(.notConnectedToInternet) }
        )

        let discovered = try await attestor.discoverRouter()

        XCTAssertNil(discovered)
        XCTAssertEqual(recorder.hosts, [], "No router is tried, and Tinfoil's list isn't fetched.")
    }

    func testTheRouterListIsShuffled() async throws {
        let list = ["router-a.example", "router-b.example"]
        let first = Box<Set<String>>(value: [])
        for _ in 0..<64 {
            let attestor = Attestor(
                verifier: FakeVerifier(),
                fetch: noDirectFetch,
                retryDelay: 0,
                fetchAttestation: Recorder().fetcher,
                fetchRouterList: RouterListFetcher { list }
            )
            if let discovered = try await attestor.discoverRouter() {
                first.value.insert(discovered.host)
            }
        }
        XCTAssertEqual(first.value, Set(list), "Either router is tried first.")
        XCTAssertEqual(list, ["router-a.example", "router-b.example"], "The caller's list is unchanged.")
    }

    // MARK: - Errors

    func testAFetcherErrorIsANetworkErrorUnlessItHasACategory() async {
        let plain = AttestationFetcher { _, _ in throw URLError(.cannotConnectToHost) }
        do {
            _ = try await plain(host: "enclave.example", nonce: nonce)
            XCTFail("expected an error")
        } catch TinfoilError.networkError(let failure) {
            XCTAssertTrue(failure.message.contains("enclave.example"), failure.message)
        } catch {
            XCTFail("expected a network error, got \(error)")
        }

        let configured = AttestationFetcher { _, _ in throw TinfoilError.configuration("not allowed") }
        let attestor = Attestor(verifier: FakeVerifier(), fetch: noDirectFetch, retryDelay: 0, fetchAttestation: configured)
        do {
            _ = try await attestor.attest(host: "enclave.example", relay: nil, pin: Pin(repo: "org/repo"))
            XCTFail("expected an error")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertEqual(failure.message, "not allowed", "An SDK error keeps its category.")
        } catch {
            XCTFail("expected a configuration error, got \(error)")
        }
    }

    func testAFetcherIsBoundedByItsTimeout() async {
        let hanging = AttestationFetcher { _, _ in
            try await Task.sleep(nanoseconds: 60_000_000_000)
            return Data()
        }
        do {
            _ = try await hanging(host: "enclave.example", nonce: nonce, timeout: 0.05)
            XCTFail("expected a timeout")
        } catch TinfoilError.networkError(let failure) {
            XCTAssertTrue(failure.message.contains("timed out"), failure.message)
        } catch {
            XCTFail("expected a network error, got \(error)")
        }
    }

    func testTheCallersCancellationPassesThrough() async {
        let started = expectation(description: "the fetch started")
        let hanging = AttestationFetcher { _, _ in
            started.fulfill()
            try await Task.sleep(nanoseconds: 60_000_000_000)
            return Data()
        }
        let task = Task { try await hanging(host: "enclave.example", nonce: self.nonce) }
        await fulfillment(of: [started], timeout: 5)
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected the cancellation")
        } catch is CancellationError {
        } catch {
            XCTFail("expected a CancellationError, got \(error)")
        }
    }

    func testADocumentForAnotherNonceIsAnAttestationError() async {
        let stale = AttestationFetcher { _, _ in Data("ok:\(String(repeating: "ee", count: 31))".utf8) }
        let attestor = Attestor(verifier: FakeVerifier(), fetch: noDirectFetch, retryDelay: 0, fetchAttestation: stale)
        do {
            _ = try await attestor.attest(host: "enclave.example", relay: nil, pin: Pin(repo: "org/repo"))
            XCTFail("expected an error")
        } catch TinfoilError.attestationError {
        } catch {
            XCTFail("expected an attestation error, got \(error)")
        }
    }
}
