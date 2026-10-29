import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A client for one of Tinfoil's routers, which forwards requests to the
/// enclaves serving each model, matching tinfoil-go's `NewRouterHTTPClient`.
/// It picks and verifies a router before its initializer returns, then sends
/// only to that router, verifying it again once the verification expires or
/// the router rejects its key.
///
/// It exists only while the router is Tinfoil's default route. For inference
/// that doesn't depend on the route, use `TinfoilAI`.
public final class RouterHTTPClient: Sendable {
    let connection: EnclaveConnection

    /// Picks the first of Tinfoil's routers that verifies, and otherwise the
    /// fallback router, and verifies it. Routers are tried for at most 30
    /// seconds before falling back, and each call discovers again. With an
    /// attestation relay, the relay is asked for the fallback router instead.
    /// The configuration is checked before any network I/O.
    ///
    /// - Parameters:
    ///   - transportMode: How requests are protected; EHBP by default
    ///   - baseURL: An HTTPS proxy requests are sent to, which requires
    ///     `.ehbp` because the router's origin isn't known before discovery.
    ///     Requests carry `X-Tinfoil-Enclave-Url` so it can forward them.
    ///   - attestationRelay: Host, with an optional port, that forwards
    ///     attestation requests to the fallback router
    ///   - policy: Checks beyond the defaults
    ///   - userCacheSecret: Scopes the router's prompt cache for the client's
    ///     requests. When unset, it is resolved from
    ///     `TINFOIL_USER_CACHE_SECRET` or a generated value persisted at
    ///     `~/.tinfoil/user_cache_secret`. A non-empty `user_cache_secret`
    ///     string in a request's JSON body overrides it. Use an opaque random
    ///     value, not a raw user ID or API key.
    ///   - onEnclaveVerified: Called each time a router's evidence verifies,
    ///     before its keys are used; throw to reject it, and discovery moves
    ///     to the next router.
    ///   - onVerificationResult: Called with each verification's final result.
    ///     It only observes.
    public convenience init(
        transportMode: TransportMode = .ehbp,
        baseURL: URL? = nil,
        attestationRelay: String? = nil,
        policy: VerificationPolicy = VerificationPolicy(),
        userCacheSecret: String? = nil,
        onEnclaveVerified: EnclaveVerifiedCallback? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) async throws {
        try await self.init(verifying: EnclaveConnection.router(
            attestor: Attestor(verifier: try GoAttestationVerifier(policy: policy), onEnclaveVerified: onEnclaveVerified),
            transportMode: transportMode,
            baseURL: baseURL,
            attestationRelay: attestationRelay,
            userCacheSecret: userCacheSecret,
            onVerificationResult: onVerificationResult
        ))
    }

    /// Verifies connection before the client is handed out. Discovery leaves
    /// its fallback router unverified, so this verifies it.
    init(verifying connection: EnclaveConnection) async throws {
        try await connection.ensureUsable()
        self.connection = connection
    }

    /// How the client protects its requests
    public var transportMode: TransportMode { connection.transportMode }

    /// The URL requests are sent to: the `baseURL` the client was created
    /// with, or the router's own origin. Relative URLs passed to
    /// `data(for:)` resolve against it.
    public var baseURL: URL { connection.baseURL }

    /// The host of the router the client chose. It stays the router's host
    /// when `baseURL` is a proxy.
    public var enclave: String { connection.enclave }

    /// The repository the router is verified against
    public var repo: String { connection.repo }

    /// The last successful verification, without checking it. It may have
    /// expired or been rejected; use `ensureVerified()` for one that is valid.
    public var current: Verification? {
        get async { await connection.current }
    }

    /// Returns a verification that is valid now, verifying first only if the
    /// cached one has expired. A returned verification means requests can be
    /// sent.
    @discardableResult
    public func ensureVerified() async throws -> Verification {
        try await connection.ensureVerified()
    }

    /// Verifies the router again, even if the cached verification is still
    /// valid. It stays with the router chosen at creation.
    @discardableResult
    public func reverify() async throws -> Verification {
        try await connection.reverify()
    }

    /// Loads a request from the router, as `URLSession.data(for:)` does. See
    /// `EnclaveHTTPClient.data(for:)`; the same rules apply.
    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await connection.data(for: request)
    }

    /// Loads a URL from the router, as `URLSession.data(from:)` does.
    public func data(from url: URL) async throws -> (Data, HTTPURLResponse) {
        try await connection.data(from: url)
    }
}
