import Foundation

/// The SDK's half of attestation: it fetches each document with its own
/// networking and hands the bytes to the TinfoilGo verifier, which makes every
/// trust decision. It keeps no state; callers decide when to attest again.
struct Attestor: Sendable {
    typealias Fetch = @Sendable (URL) async throws -> Data

    /// A router discovery verified, and the host it was fetched from
    struct DiscoveredRouter: Sendable {
        let host: String
        let verification: Verification
    }

    private let verifier: any AttestationVerifier
    private let fetch: Fetch
    private let retryDelay: TimeInterval
    private let discoveryTimeout: TimeInterval
    private let now: @Sendable () -> ContinuousClock.Instant
    private let verificationCheck: VerificationCheck?
    /// The caller's way of obtaining documents, in place of `fetch`
    private let fetchAttestation: AttestationFetcher?
    /// The caller's way of obtaining the router list, in place of `fetch`
    private let fetchRouterList: RouterListFetcher?
    /// Orders the router list before discovery tries it
    private let shuffle: @Sendable ([String]) -> [String]

    /// - Parameters:
    ///   - retryDelay: Wait before the one retry of a failed fetch or
    ///     verification
    ///   - discoveryTimeout: How long fetching the router list and trying
    ///     routers may take together before the fallback router is used
    ///   - now: The monotonic clock the discovery deadline is measured on, so
    ///     a change to the wall clock cannot move it.
    ///   - verificationCheck: The caller's check on each enclave whose evidence
    ///     verifies.
    ///   - fetchAttestation: How documents are obtained; nil fetches them with
    ///     `fetch`, directly from each enclave.
    ///   - fetchRouterList: How the router list is obtained; nil fetches
    ///     Tinfoil's with `fetch`.
    ///   - shuffle: Orders the router list; a uniformly random order by
    ///     default, so that clients spread across routers.
    init(
        verifier: any AttestationVerifier,
        fetch: @escaping Fetch = { try await DocumentFetcher().fetch($0) },
        retryDelay: TimeInterval = 1,
        discoveryTimeout: TimeInterval = 30,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
        verificationCheck: VerificationCheck? = nil,
        fetchAttestation: AttestationFetcher? = nil,
        fetchRouterList: RouterListFetcher? = nil,
        shuffle: @escaping @Sendable ([String]) -> [String] = { $0.shuffled() }
    ) {
        self.verifier = verifier
        self.fetch = fetch
        self.retryDelay = retryDelay
        self.discoveryTimeout = discoveryTimeout
        self.now = now
        self.verificationCheck = verificationCheck
        self.fetchAttestation = fetchAttestation
        self.fetchRouterList = fetchRouterList
        self.shuffle = shuffle
    }

    /// Throws the configuration error that every verification against pin
    /// would end in, without any I/O.
    func checkPinVerifiability(_ pin: Pin) throws {
        try verifier.checkPinVerifiability(pin)
    }

    /// Verifies host against pin, fetching through relay when it is not nil.
    /// A failed fetch or verification is retried once against fresh evidence;
    /// a configuration error is not.
    func attest(host: String, relay: String?, pin: Pin) async throws -> Verification {
        let verified: Verification
        do {
            verified = try await verifyOnce(host: host, relay: relay, pin: pin)
        } catch let error as TinfoilError where error.isRetryable {
            try await Task.sleep(nanoseconds: UInt64(retryDelay * 1_000_000_000))
            verified = try await verifyOnce(host: host, relay: relay, pin: pin)
        }
        return try accepted(verified, host: host)
    }

    /// Returns the host and verification of the first router of the list, in
    /// a random order, that verifies against the router pin, trying each
    /// once, or nil when none does. The caller then uses the fallback router, which it verifies
    /// itself. A router list that cannot be fetched or read leaves only the
    /// fallback, and so does reaching discoveryTimeout, however many routers
    /// are left.
    func discoverRouter() async throws -> DiscoveredRouter? {
        let discovered = await firstVerifiedRouter(pin: TinfoilConstants.routerPin)
        try Task.checkCancellation()
        return discovered
    }

    /// The first discovered router that verifies before discoveryTimeout, or
    /// nil. Reaching the deadline cancels the fetch in flight, and discovery
    /// returns then even if a caller's fetcher ignores the cancellation.
    private func firstVerifiedRouter(pin: Pin) async -> DiscoveredRouter? {
        let deadline = now().advanced(by: .seconds(discoveryTimeout))
        let discovered = try? await untilDeadline(discoveryTimeout) { () -> DiscoveredRouter? in
            for router in await discoveredRouters() {
                // The deadline can pass before the timer cancels this task,
                // as when a probe's own timeout ends with it.
                guard !Task.isCancelled, now() < deadline else {
                    return nil
                }
                if let verified = try? await attestOnce(host: router, relay: nil, pin: pin) {
                    return DiscoveredRouter(host: router, verification: verified)
                }
            }
            return nil
        }
        return discovered ?? nil
    }

    private func attestOnce(host: String, relay: String?, pin: Pin) async throws -> Verification {
        try accepted(await verifyOnce(host: host, relay: relay, pin: pin), host: host)
    }

    private func verifyOnce(host: String, relay: String?, pin: Pin) async throws -> Verification {
        let nonce = verifier.newNonce()
        let document: Data
        if let fetchAttestation {
            document = try await fetchAttestation(host: host, nonce: nonce)
        } else {
            document = try await fetch(verifier.attestationURL(host: host, relay: relay, nonce: nonce))
        }
        return try verifier.verify(document: document, nonce: nonce, pin: pin)
    }

    /// A rejection is a decision about this evidence, so callers check it
    /// outside any retry; during discovery the next router is tried instead.
    private func accepted(_ verification: Verification, host: String) throws -> Verification {
        guard let verificationCheck else {
            return verification
        }
        do {
            try verificationCheck(verification)
        } catch {
            throw TinfoilError.attestation("verification check rejected \(host): \(error)")
        }
        return verification
    }

    /// The router list, in the order that discovery tries it. The list is
    /// untrusted: each entry is only a host to try, and is verified like any
    /// other. A list that can't be obtained or read, for any reason, is
    /// empty.
    private func discoveredRouters() async -> [String] {
        let list: [String]?
        if let fetchRouterList {
            list = try? await fetchRouterList.fetch()
        } else {
            list = try? await RouterListFetcher.parseRouterList(fetch(TinfoilConstants.routerListURL))
        }
        return shuffle(list ?? [])
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
