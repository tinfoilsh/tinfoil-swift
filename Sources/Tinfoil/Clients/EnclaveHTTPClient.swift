import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// How a client protects its traffic to an enclave
public enum TransportMode: Sendable, Equatable {
    /// Pins each connection to the attested TLS key. It protects the whole
    /// request and response, and needs a direct connection to the enclave.
    case tls
    /// Seals request and response bodies to the attested HPKE key, so they
    /// stay private through a proxy. The method, URL and headers aren't
    /// sealed, and neither is a request without a body or its response.
    /// Protocol upgrades, such as WebSockets, and CONNECT tunnels are refused.
    case ehbp
}

/// A client whose requests reach only one attested enclave that you name.
/// It is verified before its initializer returns, and verifies again by
/// itself before a request once the verification expires or the enclave
/// rejects its key.
public final class EnclaveHTTPClient: Sendable {
    let connection: EnclaveConnection

    /// Creates a client for the enclave at `enclave` and verifies it. The
    /// configuration is checked before any network I/O, so a misconfigured
    /// client fails without contacting the enclave; an enclave that fails
    /// verification fails here rather than on the first request.
    ///
    /// - Parameters:
    ///   - enclave: Host of the enclave, such as "inference.tinfoil.sh"
    ///   - repo: The trusted owner/name[@tag][@sha256:digest] the enclave's
    ///     code must come from
    ///   - transportMode: How requests are protected; pinned TLS by default
    ///   - baseURL: Where requests are sent: a path on the enclave's own
    ///     origin, or an HTTPS proxy on another origin, which requires
    ///     `.ehbp`. Requests to a proxy carry `X-Tinfoil-Enclave-Url` so it can
    ///     forward them to the enclave.
    ///   - attestationRelay: Host, with an optional port, that forwards
    ///     attestation requests to the enclave
    ///   - policy: Checks beyond the defaults
    ///   - userCacheSecret: Scopes the prompt cache of the client's requests.
    ///     Only Tinfoil's router reads it, so it is sent only when set. A
    ///     non-empty `user_cache_secret` string in a request's JSON body
    ///     overrides it. Use an opaque random value, not a raw user ID or API
    ///     key.
    ///   - onEnclaveVerified: Called each time the enclave's evidence
    ///     verifies, before its keys are used; throw to reject it.
    ///   - onVerificationResult: Called with each verification's final result.
    ///     It only observes.
    public convenience init(
        enclave: String,
        repo: String,
        transportMode: TransportMode = .tls,
        baseURL: URL? = nil,
        attestationRelay: String? = nil,
        policy: VerificationPolicy = VerificationPolicy(),
        userCacheSecret: String? = nil,
        onEnclaveVerified: EnclaveVerifiedCallback? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) async throws {
        try await self.init(verifying: Self.connection(
            enclave: enclave,
            repo: repo,
            transportMode: transportMode,
            baseURL: baseURL,
            attestationRelay: attestationRelay,
            userCacheSecret: userCacheSecret,
            attestor: Attestor(verifier: try GoAttestationVerifier(policy: policy), onEnclaveVerified: onEnclaveVerified),
            onVerificationResult: onVerificationResult
        ))
    }

    /// The connection `init(enclave:repo:…)` verifies, built without network
    /// I/O. Only Tinfoil's router reads the cache secret, so an unset one
    /// stays unset.
    static func connection(
        enclave: String,
        repo: String,
        transportMode: TransportMode,
        baseURL: URL?,
        attestationRelay: String?,
        userCacheSecret: String?,
        attestor: Attestor,
        onVerificationResult: VerificationResultCallback?
    ) throws -> EnclaveConnection {
        try EnclaveConnection(
            handle: EnclaveHandle(
                enclave: enclave,
                repo: repo,
                attestationRelay: attestationRelay,
                attestor: attestor,
                onVerificationResult: onVerificationResult
            ),
            transportMode: transportMode,
            baseURL: baseURL,
            userCacheSecret: userCacheSecret ?? ""
        )
    }

    /// Verifies connection before the client is handed out.
    init(verifying connection: EnclaveConnection) async throws {
        try await connection.ensureUsable()
        self.connection = connection
    }

    /// How the client protects its requests
    public var transportMode: TransportMode { connection.transportMode }

    /// The URL requests are sent to: the `baseURL` the client was created
    /// with, or the enclave's own origin. Relative URLs passed to
    /// `data(for:)` resolve against it.
    public var baseURL: URL { connection.baseURL }

    /// The host of the enclave the client verifies. It stays the enclave's
    /// host when `baseURL` is a proxy.
    public var enclave: String { connection.enclave }

    /// The repository the enclave is verified against, with any tag or
    /// digest pins
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

    /// Verifies the enclave again, even if the cached verification is still
    /// valid.
    @discardableResult
    public func reverify() async throws -> Verification {
        try await connection.reverify()
    }

    /// Loads a request from the enclave, as `URLSession.data(for:)` does,
    /// protected by the client's transport mode. A URL without a host resolves
    /// against `baseURL`; an absolute URL must be HTTPS on `baseURL`'s origin,
    /// and so must any redirect, so credentials never leave it. A redirect
    /// elsewhere fails with `TinfoilError.configurationError`.
    ///
    /// If the enclave no longer presents or accepts the verified key, the
    /// client verifies again and retries once when that is safe. Over TLS, a
    /// key that still doesn't match fails with `TinfoilError.attestationError`;
    /// under EHBP, a refreshed key the enclave still rejects fails with EHBP's
    /// key-configuration error.
    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await connection.data(for: request)
    }

    /// Loads a URL from the enclave, as `URLSession.data(from:)` does. See
    /// `data(for:)`.
    public func data(from url: URL) async throws -> (Data, HTTPURLResponse) {
        try await connection.data(from: url)
    }
}
