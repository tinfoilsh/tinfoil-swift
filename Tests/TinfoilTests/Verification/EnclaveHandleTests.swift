import XCTest
import Foundation
@testable import Tinfoil

/// How EnclaveHandle verifies its enclave and keeps the result, using the
/// stand-ins from AttestationTestDoubles.swift in place of the network and Go.
final class EnclaveHandleTests: XCTestCase {
    private func handle(
        enclave: String = "enclave.example",
        pin: Pin = Pin(repo: "org/repo"),
        relay: String? = nil,
        network: FakeNetwork,
        clock: ManualClock = ManualClock()
    ) -> EnclaveHandle {
        EnclaveHandle(
            enclave: enclave,
            pin: pin,
            attestationRelay: relay,
            attestor: Attestor(verifier: FakeVerifier(now: { clock.now }), fetch: { try network.fetch($0) }, retryDelay: 0),
            now: { clock.now }
        )
    }

    private func approving() -> FakeNetwork {
        FakeNetwork { url, _ in
            url.host == "atc.tinfoil.sh" ? #"["router-a.example"]"# : FakeNetwork.document("ok", for: url)
        }
    }

    func testVerifiesTheConfiguredEnclave() async throws {
        let network = approving()
        let handle = handle(enclave: "enclave.example", pin: Pin(repo: "org/repo"), network: network)

        let verification = try await handle.reverify()

        XCTAssertEqual(verification.verifiedFacts?.configRepo, "org/repo")
        XCTAssertEqual(network.urls.map(\.host), ["enclave.example"])
        let latest = await handle.lastVerificationAttempt
        XCTAssertEqual(latest?.report, verification)
    }

    func testEnsureVerifiedVerifiesWhenThereIsNone() async throws {
        let network = approving()
        let handle = handle(enclave: "enclave.example", network: network)

        let current = try await handle.ensureVerified()

        XCTAssertEqual(network.urls.count, 1)
    }

    func testEnsureVerifiedReusesAFreshOne() async throws {
        let network = approving()
        let clock = ManualClock()
        let handle = handle(enclave: "enclave.example", network: network, clock: clock)
        let verified = try await handle.reverify()

        clock.advance(by: verified.freshnessExpiresAt.timeIntervalSince(clock.now) - 1)
        let current = try await handle.ensureVerified()

        XCTAssertEqual(current, verified)
        XCTAssertEqual(network.urls.count, 1, "A fresh verification is not attested again.")
    }

    func testEnsureVerifiedRenewsAnExpiredOne() async throws {
        let network = approving()
        let clock = ManualClock()
        let handle = handle(enclave: "enclave.example", network: network, clock: clock)
        let verified = try await handle.reverify()

        clock.advance(by: verified.freshnessExpiresAt.timeIntervalSince(clock.now))
        let current = try await handle.ensureVerified()

        XCTAssertNotEqual(current, verified)
        XCTAssertGreaterThan(current.freshnessExpiresAt, clock.now)
        XCTAssertEqual(network.urls.count, 2, "At its deadline the verification is renewed.")
    }

    func testReverifyAlwaysAttestsAgain() async throws {
        let network = approving()
        let handle = handle(enclave: "enclave.example", network: network)

        _ = try await handle.reverify()
        _ = try await handle.reverify()

        XCTAssertEqual(network.urls.count, 2)
    }

    func testAFailedAttestationDiscardsAFreshVerification() async throws {
        let verdict = Verdict("ok")
        let network = FakeNetwork { url, _ in FakeNetwork.document(verdict.value, for: url) }
        let handle = handle(enclave: "enclave.example", network: network)
        let first = try await handle.reverify()

        verdict.value = "reject"
        do {
            _ = try await handle.reverify()
            XCTFail("a rejected attestation must fail verification")
        } catch TinfoilError.attestationError {
        }

        let discarded = await handle.usable
        XCTAssertNil(discarded, "A verification that the enclave no longer backs is not used.")
        let last = await handle.lastVerificationAttempt
        XCTAssertNotNil(last?.error?.verificationError, "lastVerificationAttempt returns the failure, not the earlier success \(first).")
        let attempts = network.urls.count
        do {
            _ = try await handle.ensureVerified()
            XCTFail("the discarded verification must not be returned")
        } catch TinfoilError.attestationError {
        }
        XCTAssertGreaterThan(network.urls.count, attempts, "The next use verifies again.")

        verdict.value = "ok"
        let recovered = try await handle.ensureVerified()
        let latest = await handle.lastVerificationAttempt
        XCTAssertEqual(latest?.report, recovered, "Once the enclave verifies again, it is used again.")
    }

    func testOtherFailuresKeepAFreshVerification() async throws {
        let verdict = Verdict("ok")
        let network = FakeNetwork { url, _ in
            if verdict.value == "offline" {
                throw TinfoilError.network("attestation source unreachable")
            }
            return FakeNetwork.document(verdict.value, for: url)
        }
        let handle = handle(enclave: "enclave.example", network: network)
        let first = try await handle.reverify()

        for failure in ["offline", "config"] {
            verdict.value = failure
            do {
                _ = try await handle.reverify()
                XCTFail("the \(failure) run must fail")
            } catch TinfoilError.networkError, TinfoilError.configurationError {
            }
            let usable = await handle.usable
            XCTAssertEqual(usable, first, "A \(failure) failure keeps the verification.")
            let latest = await handle.lastVerificationAttempt
            XCTAssertNotNil(latest?.error, "lastVerificationAttempt returns the \(failure) failure.")
        }

        let attempts = network.urls.count
        let current = try await handle.ensureVerified()
        XCTAssertEqual(current, first)
        XCTAssertEqual(network.urls.count, attempts, "The kept verification is used without verifying again.")
    }

    func testARejectedEnclaveDiscardsTheVerification() async throws {
        let verified = Recorder<String>()
        let network = approving()
        let handle = EnclaveHandle(
            enclave: "enclave.example",
            pin: Pin(repo: "org/repo"),
            attestationRelay: nil,
            attestor: Attestor(
                verifier: FakeVerifier(),
                fetch: { try network.fetch($0) },
                retryDelay: 0,
                verificationCheck: { facts in
                    if verified.record(facts.codeDigest) > 1 {
                        throw Refusal()
                    }
                }
            )
        )
        let first = try await handle.reverify()

        do {
            _ = try await handle.reverify()
            XCTFail("a rejected enclave must fail the run")
        } catch let error as TinfoilError where error.isRefusal {
        }

        let usable = await handle.usable
        XCTAssertNil(usable, "The verification check's rejection discards it as a failed attestation does.")
        let latest = await handle.lastVerificationAttempt
        XCTAssertEqual(latest?.error?.isRefusal, true, "lastVerificationAttempt returns the rejection, not \(first).")
        XCTAssertNil(latest?.error?.verificationError, "A rejection by the check has no report.")
    }

    func testEachRunReportsItsResult() async throws {
        let results = Recorder<Result<VerificationReport, TinfoilError>>()
        let network = FakeNetwork { url, previous in
            FakeNetwork.document(previous == 0 ? "ok" : "reject", for: url)
        }
        let handle = EnclaveHandle(
            enclave: "enclave.example",
            pin: Pin(repo: "org/repo"),
            attestationRelay: nil,
            attestor: Attestor(verifier: FakeVerifier(), fetch: { try network.fetch($0) }, retryDelay: 0),
            onVerificationAttempt: { _, result in results.record(result) }
        )

        let first = try await handle.reverify()
        _ = try? await handle.reverify()

        // The second run's first attempt is retried, and each attempt is
        // reported.
        guard results.values.count == 3,
              case .success(let reported) = results.values[0],
              case .failure(.attestationError) = results.values[1],
              case .failure(.attestationError) = results.values[2] else {
            return XCTFail("expected a success then two failures, got \(results.values)")
        }
        XCTAssertEqual(reported, first)
    }

    /// A handle whose attestation fetch waits on gate, reporting each one it
    /// starts. A fetch checks for cancellation once it resumes, so a
    /// cancelled verification fails rather than finishing unnoticed.
    private func gatedHandle(
        gate: AsyncGate,
        verifications: VerificationCounter,
        onVerificationAttempt: VerificationCallback? = nil
    ) -> EnclaveHandle {
        let network = approving()
        let fetch: Attestor.Fetch = { url in
            verifications.started()
            await gate.wait()
            try Task.checkCancellation()
            return try network.fetch(url)
        }
        return EnclaveHandle(
            enclave: "enclave.example",
            pin: Pin(repo: "org/repo"),
            attestationRelay: nil,
            attestor: Attestor(verifier: FakeVerifier(), fetch: fetch, retryDelay: 0),
            onVerificationAttempt: onVerificationAttempt
        )
    }

    func testConcurrentCallsShareOneVerification() async throws {
        let gate = AsyncGate()
        let verifications = VerificationCounter(
            first: expectation(description: "verification started"),
            more: expectation(description: "a second verification")
        )
        let results = Recorder<Result<VerificationReport, TinfoilError>>()
        let handle = gatedHandle(gate: gate, verifications: verifications, onVerificationAttempt: { _, result in results.record(result) })

        let calls = (0..<3).map { _ in Task { try await handle.reverify() } }
        await fulfillment(of: [verifications.first], timeout: 1)
        // Inverted: passes only if no other call starts its own verification
        // while the first is held.
        await fulfillment(of: [verifications.more], timeout: 0.2)
        await gate.open()

        var returned: [VerificationReport] = []
        for call in calls {
            returned.append(try await call.value)
        }
        XCTAssertTrue(returned.allSatisfy { $0 == returned[0] }, "Every call gets the shared verification.")
        XCTAssertEqual(verifications.count, 1)
        XCTAssertEqual(results.values.count, 1, "A shared run reports its result once.")
    }

    func testCancellingOneCallLeavesTheSharedVerificationRunning() async throws {
        let gate = AsyncGate()
        let verifications = VerificationCounter(
            first: expectation(description: "verification started"),
            more: expectation(description: "a second verification")
        )
        let handle = gatedHandle(gate: gate, verifications: verifications)

        let cancelledReturned = expectation(description: "the cancelled call returned")
        let cancelled = Task {
            defer { cancelledReturned.fulfill() }
            return try await handle.reverify()
        }
        await fulfillment(of: [verifications.first], timeout: 1)
        let waiting = Task { try await handle.reverify() }
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
        let latest = await handle.lastVerificationAttempt
        XCTAssertEqual(latest?.report, verification)
        await fulfillment(of: [verifications.more], timeout: 0.1)
        XCTAssertEqual(verifications.count, 1)
    }
}

/// Counts verifications started, fulfilling first on the first and more on
/// any after it, which tests invert to assert there is no second.
private final class VerificationCounter: @unchecked Sendable {
    let first: XCTestExpectation
    let more: XCTestExpectation
    private let lock = NSLock()
    private var _count = 0

    init(first: XCTestExpectation, more: XCTestExpectation) {
        self.first = first
        self.more = more
        more.isInverted = true
        // Without single-flight every caller verifies; let the inverted wait
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
