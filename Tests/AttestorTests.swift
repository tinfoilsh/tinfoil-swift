import XCTest
import Foundation
@testable import TinfoilAI

/// Stands in for the Go verifier. A document is "<verdict>:<nonce hex>"; the
/// stand-in refuses one whose nonce is not the one it was given, so the tests
/// also prove the attestor carries a single nonce through each attempt.
private final class FakeVerifier: AttestationVerifier, @unchecked Sendable {
    private let lock = NSLock()
    private var issued: UInt8 = 0
    private var _repos: [String] = []

    var repos: [String] {
        lock.lock()
        defer { lock.unlock() }
        return _repos
    }

    func newNonce() -> Data {
        lock.lock()
        defer { lock.unlock() }
        issued += 1
        return Data(repeating: issued, count: 32)
    }

    func attestationURL(host: String, relay: String?, nonce: Data) throws -> URL {
        var url = "https://\(relay ?? host)/.well-known/tinfoil-attestation?nonce=\(nonce.hexString)"
        if relay != nil {
            url += "&enclave=\(host)"
        }
        return URL(string: url)!
    }

    func verify(document: Data, nonce: Data, repo: String, enclaveHost: String) throws -> Verification {
        lock.lock()
        _repos.append(repo)
        lock.unlock()
        let parts = String(decoding: document, as: UTF8.self).split(separator: ":").map(String.init)
        guard parts.count == 2, parts[1] == nonce.hexString else {
            throw TinfoilError.attestationError("document is not bound to the nonce")
        }
        switch parts[0] {
        case "ok":
            return .stub(host: enclaveHost)
        case "config":
            throw TinfoilError.invalidConfiguration("bad repo")
        default:
            throw TinfoilError.attestationError("rejected")
        }
    }
}

/// Serves each fetch from a script and records the URLs asked for.
private final class FakeNetwork: @unchecked Sendable {
    private let lock = NSLock()
    private var _urls: [URL] = []
    private let respond: (URL, Int) throws -> String

    /// respond receives the URL and how many times its host has been fetched
    /// before.
    init(respond: @escaping (URL, Int) throws -> String) {
        self.respond = respond
    }

    var urls: [URL] {
        lock.lock()
        defer { lock.unlock() }
        return _urls
    }

    func fetch(_ url: URL) throws -> Data {
        lock.lock()
        let previous = _urls.filter { $0.host == url.host }.count
        _urls.append(url)
        lock.unlock()
        return Data(try respond(url, previous).utf8)
    }

    /// A document with the given verdict, bound to the nonce in url.
    static func document(_ verdict: String, for url: URL) -> String {
        let nonce = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?.first { $0.name == "nonce" }?.value ?? ""
        return "\(verdict):\(nonce)"
    }
}

private extension Verification {
    static func stub(host: String) -> Verification {
        Verification(
            enclaveHost: host,
            configRepo: TinfoilConstants.defaultGithubRepo,
            codeDigest: "abc123",
            codeTag: nil,
            codeMeasurement: nil,
            enclaveMeasurement: nil,
            tlsPublicKeyFingerprint: "deadbeef",
            hpkePublicKey: "cafebabe",
            cryptoMaterial: [],
            freshnessExpiresAt: Date().addingTimeInterval(3600),
            verifiedAt: Date(),
            verifier: SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion)
        )
    }
}

final class AttestorTests: XCTestCase {
    private let routerList = URL(string: TinfoilConstants.routerListURL)!

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
