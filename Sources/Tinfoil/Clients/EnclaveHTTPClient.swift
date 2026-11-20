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

    /// The trust that the enclave is verified under. It is a copy: the client
    /// keeps its own.
    public let trust: Trust

    /// Creates a client for the enclave at `enclave` and verifies it. The
    /// configuration is checked before any network I/O, so a misconfigured
    /// client fails without contacting the enclave; an enclave that fails
    /// verification fails here rather than on the first request.
    ///
    /// - Parameters:
    ///   - enclave: Host of the enclave, such as "inference.tinfoil.sh"
    ///   - trust: Who vouches for the config that the enclave runs, such as
    ///     `.repo("owner/name@v1.2.3")` for a GitHub repository's signed
    ///     release or `.project("org/project")` for a config registry
    ///     project. `Trust` describes each kind.
    ///   - options: The client's options; each one's default applies when it
    ///     is not set
    public convenience init(
        enclave: String,
        trust: Trust,
        options: EnclaveOptions = EnclaveOptions()
    ) async throws {
        let pin = try trust.pin()
        let verifier = try (options.verifier ?? Verifier()).backend(trust: trust)
        try await self.init(verifying: Self.connection(
            enclave: enclave,
            pin: pin,
            transportMode: options.transportMode,
            baseURL: options.baseURL,
            attestationRelay: options.attestationRelay,
            userCacheSecret: options.userCacheSecret,
            attestor: Attestor(verifier: verifier, verificationCheck: options.verificationCheck),
            onVerificationResult: options.onVerificationResult
        ), trust: trust)
    }

    /// The connection `init(enclave:trust:options:)` verifies, built without
    /// network I/O. Only Tinfoil's router reads the cache secret, so an unset
    /// one stays unset.
    static func connection(
        enclave: String,
        pin: Pin,
        transportMode: TransportMode,
        baseURL: URL?,
        attestationRelay: String?,
        userCacheSecret: String?,
        attestor: Attestor,
        onVerificationResult: VerificationResultCallback?
    ) throws -> EnclaveConnection {
        try attestor.checkPinVerifiability(pin)
        return try EnclaveConnection(
            handle: EnclaveHandle(
                enclave: enclave,
                pin: pin,
                attestationRelay: attestationRelay,
                attestor: attestor,
                onVerificationResult: onVerificationResult
            ),
            transportMode: transportMode,
            baseURL: baseURL,
            userCacheSecret: userCacheSecret ?? ""
        )
    }

    /// Verifies connection before the client is handed out. `trust` is what
    /// the connection's pin came from; nil derives one from the pin.
    init(verifying connection: EnclaveConnection, trust: Trust? = nil) async throws {
        try await connection.ensureUsable()
        self.connection = connection
        self.trust = trust ?? Trust(pin: connection.pin)
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
