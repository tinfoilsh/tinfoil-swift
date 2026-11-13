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
    ///   - repo: The trusted owner/name[@tag][@sha256:digest] that the
    ///     enclave's config must come from. `nil` accepts any config that the
    ///     verifier's registry trust authorizes: with the default verifier,
    ///     any deployment in Tinfoil's public registry. A verifier with a
    ///     `configAuthorizer` requires `nil`. An empty string is refused, so
    ///     that a missing value can't widen the trust by accident.
    ///   - transportMode: How requests are protected; pinned TLS by default
    ///   - baseURL: Where requests are sent: a path on the enclave's own
    ///     origin, or a proxy on another origin, which requires `.ehbp`.
    ///     Requests to a proxy carry `X-Tinfoil-Enclave-Url` so it can
    ///     forward them to the enclave. It must be HTTPS, since EHBP doesn't
    ///     seal headers such as the API key; under `.ehbp`, `http` is also
    ///     accepted when the host is `localhost` or a loopback IP address,
    ///     as for a local development proxy or a sidecar.
    ///   - attestationRelay: Host, with an optional port, that forwards
    ///     attestation requests to the enclave
    ///   - verifier: The trust policy; nil selects the defaults
    ///   - userCacheSecret: Scopes the prompt cache of the client's requests.
    ///     Only Tinfoil's router reads it, so it is sent only when set. A
    ///     non-empty `user_cache_secret` string in a request's JSON body
    ///     overrides it. Use an opaque random value, not a raw user ID or API
    ///     key.
    ///   - verificationCheck: Called each time the enclave's evidence
    ///     verifies, before its keys are used; throw to reject it.
    ///   - onVerificationResult: Called with each verification's final result.
    ///     It only observes.
    public convenience init(
        enclave: String,
        repo: String?,
        transportMode: TransportMode = .tls,
        baseURL: URL? = nil,
        attestationRelay: String? = nil,
        verifier: Verifier? = nil,
        userCacheSecret: String? = nil,
        verificationCheck: VerificationCheck? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) async throws {
        try await self.init(verifying: Self.connection(
            enclave: enclave,
            repo: repo,
            transportMode: transportMode,
            baseURL: baseURL,
            attestationRelay: attestationRelay,
            userCacheSecret: userCacheSecret,
            attestor: Attestor(verifier: try verifier?.backend ?? GoAttestationVerifier(), verificationCheck: verificationCheck),
            onVerificationResult: onVerificationResult
        ))
    }

    /// The connection `init(enclave:repo:…)` verifies, built without network
    /// I/O. Only Tinfoil's router reads the cache secret, so an unset one
    /// stays unset.
    static func connection(
        enclave: String,
        repo: String?,
        transportMode: TransportMode,
        baseURL: URL?,
        attestationRelay: String?,
        userCacheSecret: String?,
        attestor: Attestor,
        onVerificationResult: VerificationResultCallback?
    ) throws -> EnclaveConnection {
        // The verifier reads "" as "any config that registry trust
        // authorizes"; only nil asks for that here.
        if repo?.isEmpty == true {
            throw TinfoilError.configuration(
                "repo must not be empty; pass nil to accept any config that the verifier's registry trust authorizes"
            )
        }
        let repo = repo ?? ""
        try attestor.checkRepoVerifiability(repo)
        return try EnclaveConnection(
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

    /// Closes the client: later requests and verifications fail with
    /// `TinfoilError.configurationError`, from this client and from any
    /// OpenAI client built over it, and a verification in progress is
    /// cancelled. Requests already sent finish. Closing again does nothing.
    public func close() async {
        await connection.close()
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
    /// digest pins, or nil when any config that the verifier's registry trust
    /// authorizes is accepted
    public var repo: String? { connection.repo.isEmpty ? nil : connection.repo }

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
    /// against `baseURL`; an absolute URL must be on `baseURL`'s exact origin,
    /// and so must any redirect, so credentials never leave it. A redirect
    /// elsewhere fails with `TinfoilError.configurationError`, except that over
    /// TLS one to plain HTTP fails with
    /// `URLError(.appTransportSecurityRequiresSecureConnection)`.
    ///
    /// If the enclave no longer presents or accepts the verified key, the
    /// client verifies again and retries once when that is safe. Over TLS, a
    /// key that still doesn't match fails with `TinfoilError.attestationError`;
    /// under EHBP, a refreshed key the enclave still rejects fails with EHBP's
    /// key-configuration error. The retry sends the same request again,
    /// headers such as `Authorization` included. To stop it, for example when
    /// the user signs out while it is pending, cancel the task awaiting this
    /// call: a request cancelled before the retry is not sent again and fails
    /// with `CancellationError`.
    ///
    /// The request's `timeoutInterval` is how long it may go without
    /// receiving data before failing with `URLError(.timedOut)`; raise it for
    /// an endpoint that works a long time before it replies. It is 60 seconds
    /// unless set.
    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await connection.data(for: request)
    }

    /// Loads a URL from the enclave, as `URLSession.data(from:)` does. See
    /// `data(for:)`.
    public func data(from url: URL) async throws -> (Data, HTTPURLResponse) {
        try await connection.data(from: url)
    }

    /// Sends a request as `data(for:)` does, but returns as soon as the
    /// response headers arrive, with the body still streaming and the
    /// session recovery token that can decrypt this one response later. Use
    /// it for a response the server stores so the client can fetch it again
    /// after an interruption, such as a chat completion. The token is this
    /// request's own, even with other requests in flight on the client.
    ///
    /// It requires `TransportMode.ehbp`; in TLS mode it fails with
    /// `TinfoilError.configurationError`. The same retry after a key rejection
    /// applies, and cancelling the task stops it in the same way. The
    /// request's `timeoutInterval` also limits each wait for the body's next
    /// chunk.
    public func recoverableBytes(for request: URLRequest) async throws -> RecoverableResponse {
        try await connection.recoverableBytes(for: request)
    }
}
