import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// How a client protects its traffic to an enclave: `.tls`, the default, or
/// `.ehbp(proxyURL:)`.
public struct Transport: Sendable, Equatable {
    let mode: TransportMode

    /// Where an EHBP client sends requests, or nil when it connects directly
    /// to the enclave. It is always nil for TLS.
    public let proxyURL: URL?

    /// Pins each connection to the attested TLS key. It protects the whole
    /// request and response, and needs a direct connection to the enclave, so
    /// it takes no URL: requests go to the enclave's own HTTPS origin.
    public static let tls = Transport(mode: .tls, proxyURL: nil)

    /// Seals request and response bodies to the attested HPKE key, so that
    /// they stay private through a proxy. The method, URL and headers aren't
    /// sealed, and neither is a request without a body or its response.
    /// Protocol upgrades, such as WebSockets, and CONNECT tunnels are refused.
    ///
    /// - Parameter proxyURL: A proxy that forwards requests to the enclave,
    ///   which requests are sent to; nil sends them directly to the enclave.
    ///   Its path, if any, is where the proxy is mounted, not the API path.
    ///   Requests to it carry `X-Tinfoil-Enclave-Url` so that it can forward
    ///   them. It must be HTTPS, since EHBP doesn't seal headers such as the
    ///   API key; `http` is accepted only when its host is `localhost` or a
    ///   loopback IP address, as for a local development proxy or a sidecar.
    ///   Request paths join under it, so a URL with credentials, a query or a
    ///   fragment, even an empty one, is refused. An enclave client also
    ///   refuses a proxy on the enclave's own origin, which is no proxy; leave
    ///   it nil to connect directly.
    public static func ehbp(proxyURL: URL? = nil) -> Transport {
        Transport(mode: .ehbp, proxyURL: proxyURL)
    }
}

/// The transport's protection, apart from where requests go
enum TransportMode: Sendable, Equatable {
    /// Pinned TLS
    case tls
    /// Bodies sealed with EHBP
    case ehbp
}

/// A client whose requests reach only one attested enclave that you name.
/// It is verified before its initializer returns, and verifies again by
/// itself before a request once the verification expires or the enclave
/// rejects its key.
///
/// It sends request bodies as they are: it never adds or changes a
/// `user_cache_secret` member, so a caller that points it at Tinfoil's
/// router and wants a scoped prompt cache sets that member in each request
/// body.
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
        try options.fetchAttestation?.relayURL.map { try EnclaveConnection.validateRelayURL($0) }
        let verifier = try GoAttestationVerifier(trust: trust, policy: options.policy)
        try await self.init(verifying: Self.connection(
            enclave: enclave,
            pin: pin,
            transportMode: options.transport.mode,
            baseURL: options.transport.proxyURL,
            attestor: Attestor(
                verifier: verifier,
                verificationCheck: options.verificationCheck,
                fetchAttestation: options.fetchAttestation
            ),
            onVerificationResult: options.onVerificationResult
        ), trust: trust)
    }

    /// The connection `init(enclave:trust:options:)` verifies, built without
    /// network I/O. It sends request bodies as they are: it never adds or
    /// changes a `user_cache_secret` member.
    static func connection(
        enclave: String,
        pin: Pin,
        transportMode: TransportMode,
        baseURL: URL?,
        attestor: Attestor,
        onVerificationResult: VerificationResultCallback?
    ) throws -> EnclaveConnection {
        if let proxyURL = baseURL {
            try EnclaveConnection.refuseEnclaveOriginProxy(proxyURL, enclave: enclave)
        }
        try attestor.checkPinVerifiability(pin)
        return try EnclaveConnection(
            handle: EnclaveHandle(
                enclave: enclave,
                pin: pin,
                attestationRelay: nil,
                attestor: attestor,
                onVerificationResult: onVerificationResult
            ),
            transportMode: transportMode,
            baseURL: baseURL,
            // The client sends bodies as they are.
            userCacheSecret: ""
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
    public var transport: Transport { connection.transport }

    /// The URL that requests are sent to: the EHBP proxy URL, or the
    /// enclave's own origin when the client connects directly. Relative URLs
    /// passed to `data(for:)` resolve against it.
    public var baseURL: URL { connection.baseURL }

    /// The host of the enclave the client verifies. It stays the enclave's
    /// host when requests go through a proxy.
    public var enclave: String { connection.enclave }

    /// The last successful verification, without checking it, or nil once a
    /// re-verification that fails attestation discards it, as `reverify()`
    /// describes. It may have expired; use `ensureVerified()` for one that is
    /// valid.
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
    ///
    /// If the new verification fails with `TinfoilError.attestationError`,
    /// this throws it and the client discards its cached verification, even
    /// one that is still valid: no later request is sent under it, and the
    /// next request verifies again, failing while the problem persists. Other
    /// failures, such as a `TinfoilError.networkError` or a cancellation,
    /// keep a cached verification that is still valid. Requests already in
    /// flight finish.
    @discardableResult
    public func reverify() async throws -> Verification {
        try await connection.reverify()
    }

    /// Loads a request from the enclave, as `URLSession.data(for:)` does,
    /// protected by the client's transport. A URL without a host resolves
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
    /// key-configuration error. If verifying again fails attestation, the
    /// cached verification is discarded, as after a failed `reverify()`. The
    /// retry sends the same request again,
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
    /// It requires the EHBP transport; over TLS it fails with
    /// `TinfoilError.configurationError`. The same retry after a key rejection
    /// applies, and cancelling the task stops it in the same way. The
    /// request's `timeoutInterval` also limits each wait for the body's next
    /// chunk.
    public func recoverableBytes(for request: URLRequest) async throws -> RecoverableResponse {
        try await connection.recoverableBytes(for: request)
    }
}
