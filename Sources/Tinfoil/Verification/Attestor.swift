import Foundation

/// The SDK's half of attestation: it fetches each document with its own
/// networking and hands the bytes to the tinfoil-go verifier, which makes every
/// trust decision. It keeps no state; callers decide when to attest again.
struct Attestor: Sendable {
    typealias Fetch = @Sendable (URL) async throws -> Data

    private let verifier: any AttestationVerifier
    private let fetch: Fetch
    private let retryDelay: TimeInterval
    private let discoveryTimeout: TimeInterval
    private let now: @Sendable () -> ContinuousClock.Instant
    private let onEnclaveVerified: EnclaveVerifiedCallback?

    /// - Parameters:
    ///   - retryDelay: Wait before the one retry of a failed fetch or
    ///     verification, as in the Go SDK.
    ///   - discoveryTimeout: How long fetching the router list and trying
    ///     routers may take together before the fallback router is used, as
    ///     in the Go SDK.
    ///   - now: The monotonic clock the discovery deadline is measured on, so
    ///     a change to the wall clock cannot move it.
    ///   - onEnclaveVerified: The caller's check on each enclave whose evidence
    ///     verifies.
    init(
        verifier: any AttestationVerifier,
        fetch: @escaping Fetch = { try await AttestationFetcher().fetch($0) },
        retryDelay: TimeInterval = 1,
        discoveryTimeout: TimeInterval = 30,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
        onEnclaveVerified: EnclaveVerifiedCallback? = nil
    ) {
        self.verifier = verifier
        self.fetch = fetch
        self.retryDelay = retryDelay
        self.discoveryTimeout = discoveryTimeout
        self.now = now
        self.onEnclaveVerified = onEnclaveVerified
    }

    /// Verifies host against repo, fetching through relay when it is not nil.
    /// A failed fetch or verification is retried once against fresh evidence;
    /// a configuration error is not.
    func attest(host: String, relay: String?, repo: String) async throws -> Verification {
        let verified: Verification
        do {
            verified = try await verifyOnce(host: host, relay: relay, repo: repo)
        } catch let error as TinfoilError where error.isRetryable {
            try await Task.sleep(nanoseconds: UInt64(retryDelay * 1_000_000_000))
            verified = try await verifyOnce(host: host, relay: relay, repo: repo)
        }
        return try accepted(verified)
    }

    /// Returns the verification of the first of Tinfoil's routers that
    /// verifies against the router repository, trying each once, or nil when
    /// none does, as tinfoil-go's router discovery does. The caller then uses
    /// the fallback router, verified on first use. A router list that cannot
    /// be fetched or read leaves only the fallback, and so does reaching
    /// discoveryTimeout, however many routers are left.
    func discoverRouter() async throws -> Verification? {
        let verified = await firstVerifiedRouter(repo: TinfoilConstants.defaultGithubRepo)
        try Task.checkCancellation()
        return verified
    }

    /// The first discovered router that verifies before discoveryTimeout, or
    /// nil. Reaching the deadline cancels the fetch in flight.
    private func firstVerifiedRouter(repo: String) async -> Verification? {
        let deadline = now().advanced(by: .seconds(discoveryTimeout))
        return await withTaskGroup(of: Verification?.self) { group in
            group.addTask {
                for router in await discoveredRouters() {
                    // The deadline can pass before the timer below cancels
                    // this task, as when a probe's own timeout ends with it.
                    guard !Task.isCancelled, now() < deadline else {
                        return nil
                    }
                    if let verified = try? await attestOnce(host: router, relay: nil, repo: repo) {
                        return verified
                    }
                }
                return nil
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(discoveryTimeout * 1_000_000_000))
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
    }

    private func attestOnce(host: String, relay: String?, repo: String) async throws -> Verification {
        try accepted(await verifyOnce(host: host, relay: relay, repo: repo))
    }

    private func verifyOnce(host: String, relay: String?, repo: String) async throws -> Verification {
        let nonce = verifier.newNonce()
        let url = try verifier.attestationURL(host: host, relay: relay, nonce: nonce)
        let document = try await fetch(url)
        return try verifier.verify(document: document, nonce: nonce, repo: repo, enclaveHost: host)
    }

    /// A rejection is a decision about this evidence, so callers check it
    /// outside any retry; during discovery the next router is tried instead.
    private func accepted(_ verification: Verification) throws -> Verification {
        guard let onEnclaveVerified else {
            return verification
        }
        do {
            try onEnclaveVerified(verification)
        } catch {
            throw TinfoilError.attestation("onEnclaveVerified rejected \(verification.enclaveHost): \(error)")
        }
        return verification
    }

    /// The router list is untrusted: each entry is only a host to try, and
    /// is verified like any other.
    private func discoveredRouters() async -> [String] {
        guard let list = try? await fetch(TinfoilConstants.routerListURL) else {
            return []
        }
        return (try? JSONDecoder().decode([String].self, from: list)) ?? []
    }
}

private extension TinfoilError {
    var isRetryable: Bool {
        switch self {
        case .networkError, .attestationError:
            return true
        default:
            return false
        }
    }
}
