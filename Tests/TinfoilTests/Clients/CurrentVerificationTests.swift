import XCTest
import Foundation
@testable import Tinfoil

/// `currentVerification`: the report of the verification that a client's
/// requests are bound to now, which `lastVerificationAttempt` leaves behind
/// after a failure that keeps it, and which expiry or a failure that discards
/// it ends.
final class CurrentVerificationTests: XCTestCase {
    /// A TLS client for enclave.example whose attestation source serves
    /// verdict's value on each fetch, on clock's time, verified before it
    /// returns. Each send records its URL and succeeds.
    private func client(
        _ verdict: Verdict,
        clock: ManualClock = ManualClock(),
        network: Recorder<URL> = Recorder(),
        sends: Recorder<String> = Recorder()
    ) async throws -> EnclaveHTTPClient {
        let source = FakeNetwork { url, _ in
            network.record(url)
            if verdict.value == "offline" {
                throw TinfoilError.network("attestation source unreachable")
            }
            return FakeNetwork.document(verdict.value, for: url)
        }
        return try await EnclaveHTTPClient(verifying: EnclaveConnection(
            handle: EnclaveHandle(
                enclave: "enclave.example",
                pin: Pin(repo: "org/repo"),
                attestationRelay: nil,
                attestor: Attestor(verifier: FakeVerifier(now: { clock.now }), fetch: { try source.fetch($0) }, retryDelay: 0),
                now: { clock.now }
            ),
            transportMode: .tls,
            baseURL: nil,
            userCacheSecret: "",
            send: { request, fingerprint in
                sends.record(fingerprint)
                return (Data("ok".utf8), HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
            }
        ))
    }

    func testItIsNilBeforeTheFirstSuccess() async throws {
        let handle = EnclaveHandle(
            enclave: "enclave.example",
            pin: Pin(repo: "org/repo"),
            attestationRelay: nil,
            attestor: Attestor(verifier: FakeVerifier(), fetch: { FakeNetwork.document("reject", for: $0).data(using: .utf8)! }, retryDelay: 0)
        )
        let before = await handle.currentVerification
        XCTAssertNil(before)
        _ = try? await handle.ensureVerified()
        let after = await handle.currentVerification
        XCTAssertNil(after, "A failed first verification leaves nothing current.")
    }

    func testItIsTheFreshVerificationWithoutIO() async throws {
        let network = Recorder<URL>()
        let client = try await client(Verdict("ok"), network: network)
        let ensured = try await client.ensureVerified()
        let fetches = network.values.count

        let current = await client.currentVerification
        XCTAssertEqual(current, ensured)
        XCTAssertEqual(network.values.count, fetches, "currentVerification fetches nothing.")
    }

    func testANetworkFailureKeepsItWhileTheLastAttemptIsTheFailure() async throws {
        let verdict = Verdict("ok")
        let network = Recorder<URL>()
        let sends = Recorder<String>()
        let client = try await client(verdict, network: network, sends: sends)
        let ensured = try await client.ensureVerified()

        verdict.value = "offline"
        do {
            _ = try await client.reverify()
            XCTFail("an unreachable attestation source must fail re-verification")
        } catch TinfoilError.networkError {
        }

        let current = await client.currentVerification
        XCTAssertEqual(current, ensured, "The cached verification is still current.")
        let last = await client.lastVerificationAttempt
        guard case .networkError? = last?.error else {
            return XCTFail("the last attempt should be the network error, got \(String(describing: last))")
        }
        let fetches = network.values.count
        _ = try await client.data(from: URL(string: "/health")!)
        XCTAssertEqual(sends.values.count, 1, "The request went through under the current verification.")
        XCTAssertEqual(network.values.count, fetches, "without verifying again.")
    }

    func testAnAttestationFailureDiscardsItUntilTheNextSuccess() async throws {
        let verdict = Verdict("ok")
        let client = try await client(verdict)
        let first = try await client.ensureVerified()

        verdict.value = "reject"
        _ = try? await client.reverify()
        let discarded = await client.currentVerification
        XCTAssertNil(discarded, "An attestation failure discards the verification.")

        verdict.value = "ok"
        let next = try await client.ensureVerified()
        XCTAssertNotEqual(next, first)
        let current = await client.currentVerification
        XCTAssertEqual(current, next)
    }

    func testItIsNilOnceTheVerificationExpires() async throws {
        let clock = ManualClock()
        let network = Recorder<URL>()
        let client = try await client(Verdict("ok"), clock: clock, network: network)
        let ensured = try await client.ensureVerified()
        let fetches = network.values.count

        clock.advance(by: 3600)
        let expired = await client.currentVerification
        XCTAssertNil(expired, "An expired verification is not current.")
        XCTAssertEqual(network.values.count, fetches, "Reading it starts no verification.")
        let last = await client.lastVerificationAttempt
        XCTAssertEqual(last?.report, ensured, "The last attempt is still the successful one.")

        let renewed = try await client.ensureVerified()
        XCTAssertNotEqual(renewed, ensured)
        let current = await client.currentVerification
        XCTAssertEqual(current, renewed)
    }
}
