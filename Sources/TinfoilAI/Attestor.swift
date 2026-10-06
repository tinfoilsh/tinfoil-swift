import Foundation

/// The SDK's half of attestation: it fetches each document with its own
/// networking and hands the bytes to the tinfoil-go verifier, which makes every
/// trust decision. It keeps no state; callers decide when to attest again.
struct Attestor: Sendable {
    typealias Fetch = @Sendable (URL) async throws -> Data

    private let verifier: any AttestationVerifier
    private let fetch: Fetch
    private let retryDelay: TimeInterval

    /// - Parameter retryDelay: Wait before the one retry of a failed fetch or
    ///   verification, as in the Go SDK.
    init(
        verifier: any AttestationVerifier,
        fetch: @escaping Fetch = { try await AttestationFetcher().fetch($0) },
        retryDelay: TimeInterval = 1
    ) {
        self.verifier = verifier
        self.fetch = fetch
        self.retryDelay = retryDelay
    }

    /// Verifies host against repo, fetching through relay when it is not nil.
    /// A failed fetch or verification is retried once against fresh evidence;
    /// a configuration error is not.
    func attest(host: String, relay: String?, repo: String) async throws -> Verification {
        do {
            return try await attestOnce(host: host, relay: relay, repo: repo)
        } catch let error as TinfoilError where error.isRetryable {
            try await Task.sleep(nanoseconds: UInt64(retryDelay * 1_000_000_000))
            return try await attestOnce(host: host, relay: relay, repo: repo)
        }
    }

    /// Verifies the first of Tinfoil's routers that verifies against the router
    /// repository, trying each once, and otherwise the fallback router. A
    /// router list that cannot be fetched or read leaves only the fallback.
    func attestDefaultRouter() async throws -> Verification {
        let repo = TinfoilConstants.defaultGithubRepo
        for router in try await discoveredRouters() {
            try Task.checkCancellation()
            do {
                return try await attestOnce(host: router, relay: nil, repo: repo)
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                continue
            }
        }
        return try await attest(host: TinfoilConstants.fallbackEnclave, relay: nil, repo: repo)
    }

    private func attestOnce(host: String, relay: String?, repo: String) async throws -> Verification {
        let nonce = verifier.newNonce()
        let url = try verifier.attestationURL(host: host, relay: relay, nonce: nonce)
        let document = try await fetch(url)
        return try verifier.verify(document: document, nonce: nonce, repo: repo, enclaveHost: host)
    }

    /// The router list is untrusted: each entry is only a host to try, and
    /// is verified like any other.
    private func discoveredRouters() async throws -> [String] {
        guard let url = URL(string: TinfoilConstants.routerListURL) else {
            return []
        }
        do {
            return try JSONDecoder().decode([String].self, from: try await fetch(url))
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            return []
        }
    }
}

private extension TinfoilError {
    /// Fetch and attestation failures may pass on a second try against fresh
    /// evidence; a configuration error will not.
    var isRetryable: Bool {
        switch self {
        case .fetchError, .attestationError:
            return true
        default:
            return false
        }
    }
}
