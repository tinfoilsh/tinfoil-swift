import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// One enclave's connection, shared by `EnclaveHTTPClient` and
/// `RouterHTTPClient`: its verification handle and the transport that ties
/// requests to the verified keys. Creating one does no network I/O, as
/// tinfoil-go's `unverifiedEnclaveHTTPClient`; the public clients verify it
/// with `ensureUsable()` before they return.
final class EnclaveConnection: Sendable {
    /// How the client protects its requests
    let transportMode: TransportMode
    /// The URL requests are sent to: the `baseURL` the client was created
    /// with, or the enclave's own origin. Relative URLs passed to
    /// `data(for:)` resolve against it.
    let baseURL: URL

    /// The host of the enclave the connection verifies: the one named, or
    /// the router discovery chose. It stays the enclave's host when `baseURL`
    /// is a proxy.
    var enclave: String { handle.enclave }

    /// The repository the enclave is verified against, with any tag or
    /// digest pins
    var repo: String { handle.repo }

    let handle: EnclaveHandle
    /// The prompt-cache secret injected into eligible request bodies, already
    /// resolved; empty injects none.
    let userCacheSecret: String
    /// The EHBP sessions, sealing to one shared verified key; nil in TLS mode.
    let ehbp: EHBPChannel?
    private let send: PinnedTLS.Send

    /// A connection to the first of Tinfoil's routers that verifies, and
    /// otherwise to the fallback router, left unverified as tinfoil-go's
    /// router discovery leaves it. With an attestation relay, the relay is
    /// asked for the fallback router instead. An unset `userCacheSecret` is
    /// resolved from the environment or the persisted secret, since this is
    /// Tinfoil's router.
    static func router(
        attestor: Attestor,
        transportMode: TransportMode,
        baseURL: URL?,
        attestationRelay: String?,
        userCacheSecret: String?,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        homeDirectory: URL? = UserCacheSecret.defaultHomeDirectory,
        onVerificationResult: VerificationResultCallback?
    ) async throws -> EnclaveConnection {
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
        return try EnclaveConnection(
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
    var current: Verification? {
        get async { await handle.current }
    }

    /// Returns a verification that is valid now, verifying first only if the
    /// cached one has expired or there is none. A returned verification means
    /// requests can be sent.
    @discardableResult
    func ensureVerified() async throws -> Verification {
        try await handle.ensureVerified()
    }

    /// Verifies the enclave again, even if the cached verification is still
    /// valid.
    @discardableResult
    func reverify() async throws -> Verification {
        try await handle.reverify()
    }

    /// Verifies the enclave, as tinfoil-go's constructors do before they
    /// return. In EHBP mode the enclave must also endorse an HPKE key, which
    /// every request is sealed to.
    func ensureUsable() async throws {
        let verified = try await handle.ensureVerified()
        if ehbp != nil {
            _ = try EHBPVerifiedEndpoint(verification: verified)
        }
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
    func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
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
    func data(from url: URL) async throws -> (Data, HTTPURLResponse) {
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
