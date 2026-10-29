import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// How a client protects its traffic to an enclave, as tinfoil-go's
/// `TransportMode` selects it.
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

/// A client whose requests reach only one attested enclave, matching
/// tinfoil-go's `EnclaveHTTPClient`. It verifies the enclave on first use, or
/// with `ensureVerified()` to fail fast, and verifies again before a request
/// once the verification expires or the enclave rejects its key.
///
/// Create one for an enclave you name with `init(enclave:repo:…)`, which does
/// no network I/O, or for one of Tinfoil's routers with `discoverRouter(…)`.
/// Pass it to `TinfoilAI.create` to send OpenAI requests through it.
public final class EnclaveHTTPClient: Sendable {
    /// How the client protects its requests
    public let transportMode: TransportMode
    /// The URL requests are sent to: the `baseURL` the client was created
    /// with, or the enclave's own origin. Relative URLs passed to
    /// `data(for:)` resolve against it.
    public let baseURL: URL

    /// The host of the enclave the client verifies: the one it was created
    /// for, or the router `discoverRouter` chose. It stays the enclave's host
    /// when `baseURL` is a proxy.
    public var enclave: String { handle.enclave }

    /// The repository the enclave is verified against, with any tag or
    /// digest pins
    public var repo: String { handle.repo }

    let handle: EnclaveHandle
    /// The prompt-cache secret injected into eligible request bodies, already
    /// resolved; empty injects none.
    let userCacheSecret: String
    /// The EHBP sessions, sealing to one shared verified key; nil in TLS mode.
    let ehbp: EHBPChannel?
    private let send: PinnedTLS.Send

    /// Creates a client for the enclave at `enclave`. It does no network I/O:
    /// the enclave is verified on the first request, or by `ensureVerified()`.
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
    ) throws {
        let attestor = Attestor(verifier: try GoAttestationVerifier(policy: policy), onEnclaveVerified: onEnclaveVerified)
        try self.init(
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

    /// Creates a client for the first of Tinfoil's routers that verifies, and
    /// otherwise for the fallback router, which is verified on first use. It
    /// tries routers for at most 30 seconds before falling back, and does
    /// network I/O: calling it again discovers again. With an attestation
    /// relay, it asks the relay for the fallback router instead.
    ///
    /// The parameters are those of `init(enclave:repo:…)`, except that
    /// requests use EHBP by default, any `baseURL` requires `.ehbp` because
    /// the router's origin isn't known before discovery, and an unset
    /// `userCacheSecret` is resolved from `TINFOIL_USER_CACHE_SECRET` or a
    /// generated value persisted at `~/.tinfoil/user_cache_secret`.
    public static func discoverRouter(
        transportMode: TransportMode = .ehbp,
        baseURL: URL? = nil,
        attestationRelay: String? = nil,
        policy: VerificationPolicy = VerificationPolicy(),
        userCacheSecret: String? = nil,
        onEnclaveVerified: EnclaveVerifiedCallback? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) async throws -> EnclaveHTTPClient {
        try await discoverRouter(
            attestor: Attestor(verifier: try GoAttestationVerifier(policy: policy), onEnclaveVerified: onEnclaveVerified),
            transportMode: transportMode,
            baseURL: baseURL,
            attestationRelay: attestationRelay,
            userCacheSecret: userCacheSecret,
            onVerificationResult: onVerificationResult
        )
    }

    static func discoverRouter(
        attestor: Attestor,
        transportMode: TransportMode,
        baseURL: URL?,
        attestationRelay: String?,
        userCacheSecret: String?,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        homeDirectory: URL? = UserCacheSecret.defaultHomeDirectory,
        onVerificationResult: VerificationResultCallback?
    ) async throws -> EnclaveHTTPClient {
        // Checked before discovery, so a misconfiguration costs no network I/O.
        guard baseURL == nil || transportMode == .ehbp else {
            throw TinfoilError.configuration(
                "a base URL requires TransportMode.ehbp when discovering the router, because the router's origin isn't known before discovery"
            )
        }
        let discovered = attestationRelay == nil ? try await attestor.discoverRouter() : nil
        if let discovered {
            onVerificationResult?(.success(discovered))
        }
        return try EnclaveHTTPClient(
            handle: EnclaveHandle(
                enclave: discovered?.enclaveHost ?? TinfoilConstants.fallbackEnclave,
                repo: TinfoilConstants.defaultGithubRepo,
                attestationRelay: attestationRelay,
                attestor: attestor,
                initial: discovered,
                onVerificationResult: onVerificationResult
            ),
            initial: discovered,
            transportMode: transportMode,
            baseURL: baseURL,
            userCacheSecret: UserCacheSecret.resolve(
                explicit: userCacheSecret,
                environment: environment,
                homeDirectory: homeDirectory
            )
        )
    }

    /// - Parameters:
    ///   - initial: The handle's initial verification, if it has one, so EHBP
    ///     need not wait on the handle to seal the first request.
    ///   - allowPlainHTTP: Accepts an `http` base URL, for tests that send
    ///     EHBP requests to a local server. Nothing else sets it.
    init(
        handle: EnclaveHandle,
        initial: Verification? = nil,
        transportMode: TransportMode,
        baseURL: URL?,
        userCacheSecret: String,
        allowPlainHTTP: Bool = false,
        send: @escaping PinnedTLS.Send = { try await PinnedTLS.send($0, expecting: $1) }
    ) throws {
        guard let enclaveOrigin = URL(string: "https://\(handle.enclave)/"), enclaveOrigin.host != nil else {
            throw TinfoilError.configuration("cannot form a URL for the enclave \(handle.enclave)")
        }
        let base = baseURL ?? enclaveOrigin
        let schemes = allowPlainHTTP ? ["https", "http"] : ["https"]
        guard schemes.contains(base.scheme?.lowercased() ?? ""), base.host != nil, base.user == nil, base.password == nil else {
            throw TinfoilError.configuration(
                "invalid base URL \(base.absoluteString): it must be HTTPS, to protect request headers, and carry no credentials"
            )
        }
        let origin = URLHelpers.origin(from: base.absoluteString)
        if transportMode == .tls, origin != URLHelpers.origin(from: enclaveOrigin.absoluteString) {
            throw TinfoilError.configuration(
                "a base URL on another origin than the enclave \(handle.enclave) requires TransportMode.ehbp, since TLS pinning needs a direct connection"
            )
        }
        self.handle = handle
        self.transportMode = transportMode
        self.baseURL = base
        self.userCacheSecret = userCacheSecret
        self.send = send
        self.ehbp = transportMode == .ehbp
            ? EHBPChannel(origin: origin, enclaveURL: "https://\(handle.enclave)", handle: handle, initial: initial, userCacheSecret: userCacheSecret)
            : nil
    }

    /// The last successful verification, without checking it. It may have
    /// expired or been rejected; use `ensureVerified()` for one that is valid.
    public var current: Verification? {
        get async { await handle.current }
    }

    /// Returns a verification that is valid now, verifying first only if the
    /// cached one has expired or there is none. A returned verification means
    /// requests can be sent.
    @discardableResult
    public func ensureVerified() async throws -> Verification {
        try await handle.ensureVerified()
    }

    /// Verifies the enclave again, even if the cached verification is still
    /// valid.
    @discardableResult
    public func reverify() async throws -> Verification {
        try await handle.reverify()
    }

    /// Loads a request from the enclave, as `URLSession.data(for:)` does,
    /// protected by the client's transport mode. A URL without a host resolves
    /// against `baseURL`; an absolute URL must be HTTPS on `baseURL`'s origin,
    /// and in TLS mode so must any redirect, so credentials never leave it.
    /// The request uses a valid verification, verifying first if needed.
    ///
    /// In TLS mode, if the enclave presents a key the attestation does not
    /// endorse before the request was sent, the client verifies again and
    /// retries once; otherwise, or if it happens again, it fails with
    /// `TinfoilError.attestationError`. Under EHBP, a rejected key is
    /// refreshed and the request replayed in the same way.
    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var resolved = request
        resolved.url = try resolve(request.url)
        if let ehbp {
            let (data, response) = try await ehbp.session.data(for: resolved, delegate: nil)
            guard let response = response as? HTTPURLResponse else {
                throw TinfoilError.network("\(resolved.url?.absoluteString ?? "the request") returned a response that is not HTTP")
            }
            return (data, response)
        }
        var headers = resolved.allHTTPHeaderFields ?? [:]
        resolved.httpBody = UserCacheSecret.provision(request: resolved, headers: &headers, clientSecret: userCacheSecret)
        resolved.allHTTPHeaderFields = headers
        return try await sendPinned(resolved)
    }

    /// Loads a URL from the enclave, as `URLSession.data(from:)` does. See
    /// `data(for:)`.
    public func data(from url: URL) async throws -> (Data, HTTPURLResponse) {
        try await data(for: URLRequest(url: url))
    }

    private func sendPinned(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var attempt = 0
        while true {
            let verification = try await handle.ensureVerified()
            do {
                return try await send(request, verification.tlsPublicKeyFingerprint)
            } catch let rejection as PinnedTLS.Rejection {
                attempt += 1
                // Replaying is safe only if the request never left: a rejection
                // on a later connection, as after a redirect, may follow one
                // that reached the enclave.
                guard attempt < 2, !rejection.requestMayHaveBeenSent else {
                    throw TinfoilError.attestation(rejection.description)
                }
                // The enclave may have rotated its key since it was verified.
                _ = try await handle.reverify()
            }
        }
    }

    /// The URL to request: a URL without a host resolves against `baseURL`,
    /// and the result, however it was written, must be HTTPS on its origin.
    private func resolve(_ url: URL?) throws -> URL {
        guard let url else {
            throw TinfoilError.configuration("the request has no URL")
        }
        let target = url.host == nil ? URL(string: url.relativeString, relativeTo: baseURL)?.absoluteURL : url
        // A URL with a scheme but no "//", such as "https:other.example/x",
        // parses with a nil host and "other.example/x" as its path, so it
        // takes the relative branch above. Having a scheme makes it an
        // absolute reference (RFC 3986 §5.2), so resolving it against the
        // base returns it unchanged. URLSession is more lenient and reads it
        // as "https://other.example/x", connecting to other.example.
        // Requiring a host refuses it explicitly, rather than relying on the
        // origin check below failing because URLHelpers.origin cannot parse it.
        guard let target, target.host != nil, target.scheme?.lowercased() == "https" else {
            throw TinfoilError.configuration("requests to the enclave must be HTTPS URLs with a host, not \(url.absoluteString)")
        }
        let origin = URLHelpers.origin(from: baseURL.absoluteString)
        guard !origin.isEmpty, URLHelpers.origin(from: target.absoluteString) == origin else {
            throw TinfoilError.configuration(
                "requests go only to \(origin) for the verified enclave \(enclave), not \(target.host ?? target.absoluteString)"
            )
        }
        return target
    }
}

/// The EHBP sessions of one client: a regular and a streaming session sealing
/// to one shared verified key, refreshed through the client's handle.
struct EHBPChannel: Sendable {
    let state: EHBPVerifiedState
    let session: EHBPURLSession
    let streamingFactory: EHBPURLSessionFactory

    init(origin: String, enclaveURL: String, handle: EnclaveHandle, initial: Verification?, userCacheSecret: String) {
        // Without a verification yet, the state starts expired, so the first
        // request takes its key from the handle.
        let endpoint = initial.flatMap { try? EHBPVerifiedEndpoint(verification: $0) }
            ?? EHBPVerifiedEndpoint(enclaveURL: enclaveURL, publicKey: Data(), expiresAt: .distantPast)
        state = EHBPVerifiedState(endpoint: endpoint, refresh: { stale in
            // A newer verification than the stale endpoint's, as one made by
            // ensureVerified() before the first request, is used as is. The
            // stale endpoint's own verification being current means the
            // enclave rejected its key, so verify again.
            let verified = try await handle.ensureVerified()
            if verified.freshnessExpiresAt == stale.expiresAt {
                let fresh = try await handle.reverify()
                return try EHBPVerifiedEndpoint(verification: fresh)
            }
            return try EHBPVerifiedEndpoint(verification: verified)
        })
        session = EHBPURLSession(baseURL: origin, verifiedState: state, userCacheSecret: userCacheSecret)
        streamingFactory = EHBPURLSessionFactory(baseURL: origin, verifiedState: state, userCacheSecret: userCacheSecret)
    }
}
