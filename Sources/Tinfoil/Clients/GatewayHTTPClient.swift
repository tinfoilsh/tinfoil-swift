import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A client for Tinfoil inference through the gateway. Each request is sealed
/// with EHBP to a verified replica of the model it names: the gateway sees the
/// method, URL and headers, and protocol upgrades, such as WebSockets, are
/// refused. A JSON object body that repeats its `model`, `user_cache_secret`
/// or `cache_salt` member is refused with `TinfoilError.configurationError`
/// before it is sent, since a server could read a different repeat from the
/// one that the client routed on.
///
/// Experimental: the gateway route is new, and this API may change or be
/// removed in a later release.
public final class GatewayHTTPClient: Sendable {
    /// Tinfoil's gateway
    public static let defaultBaseURL = URL(string: "https://inference-gateway.tinfoil.sh/v1/")!

    let router: GatewayRouter

    /// Creates a client and fetches the gateway's catalog, so that an
    /// unreachable gateway fails here rather than on the first request. The
    /// configuration is checked before any network I/O. A model's replicas
    /// are verified on its first request, so creating the client doesn't
    /// check that the catalog lists the pinned models; a request for a model
    /// that the catalog doesn't list fails.
    ///
    /// - Parameter options: The client's options; each one's default applies
    ///   when it is not set
    public convenience init(options: GatewayOptions = GatewayOptions()) async throws {
        let verificationCheck = options.verificationCheck
        let onVerificationResult = options.onVerificationResult
        let base = Self.directory(options.baseURL ?? Self.defaultBaseURL)
        try EnclaveConnection.validateBaseURL(base, transportMode: .ehbp)
        guard base.scheme?.lowercased() == "https" else {
            throw TinfoilError.configuration("invalid base URL: the gateway base URL must use HTTPS")
        }
        guard let relay = Self.authority(of: base) else {
            throw TinfoilError.configuration("invalid base URL: the gateway base URL has no host")
        }
        let attestor = { (verifier: Verifier?) throws -> Attestor in
            Attestor(verifier: try verifier?.backend ?? GoAttestationVerifier(), verificationCheck: verificationCheck)
        }
        let policy = try GatewayPolicy(
            pins: options.modelPins.mapValues { pin in (repo: pin.repo, attestor: try pin.verifier.map { try attestor($0) }) },
            pinnedOnly: options.pinnedModelsOnly,
            attestor: attestor(options.verifier)
        )
        let source: @Sendable () async throws -> Catalog
        if let catalog = options.catalog {
            source = { catalog() }
        } else {
            let cache = CatalogCache(fetch: { try await GatewayCatalog.fetch(host: relay) })
            source = { try await cache.get() }
        }
        try await self.init(router: GatewayRouter(
            baseURL: base,
            policy: policy,
            catalog: source,
            secret: UserCacheSecret.resolve(explicit: options.userCacheSecret),
            makeReplica: { replica, attestor in
                let pin = GatewayCatalog.pin(replica.reference)
                try attestor.checkPinVerifiability(pin)
                return try EnclaveConnection(
                    handle: EnclaveHandle(
                        enclave: replica.host,
                        pin: pin,
                        attestationRelay: relay,
                        attestor: attestor,
                        onVerificationResult: onVerificationResult
                    ),
                    transportMode: .ehbp,
                    baseURL: base,
                    // The router derives the cache scope itself.
                    userCacheSecret: ""
                )
            }
        ))
    }

    /// url with a trailing slash on its path, so that request paths join
    /// under it rather than replace its last segment
    static func directory(_ url: URL) -> URL {
        guard !url.path.isEmpty, !url.absoluteString.hasSuffix("/"),
              !url.absoluteString.contains(where: { $0 == "?" || $0 == "#" })
        else {
            return url
        }
        return URL(string: url.absoluteString + "/") ?? url
    }

    /// The host and any port of base, which attestation and the catalog are
    /// fetched through, with an IPv6 address in brackets
    static func authority(of base: URL) -> String? {
        guard let host = base.host, !host.isEmpty else {
            return nil
        }
        let bracketed = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        return base.port.map { "\(bracketed):\($0)" } ?? bracketed
    }

    /// Reads the catalog through router before the client is handed out.
    init(router: GatewayRouter) async throws {
        _ = try await router.models()
        self.router = router
    }

    /// Reads the catalog of the gateway at host, keeping only the models whose
    /// replicas run a bare `tinfoilsh/` repository, without a tag or digest.
    public static func fetchCatalog(host: String) async throws -> Catalog {
        try await GatewayCatalog.fetch(host: host)
    }

    /// The gateway's base URL, which requests are sent to. Relative URLs
    /// passed to `data(for:)` resolve against it.
    public var baseURL: URL { router.baseURL }

    /// The catalog's models that the client's policy serves, sorted, without
    /// verifying replicas. A failed catalog refresh doesn't fail it; only the
    /// first fetch can.
    public func models() async throws -> [String] {
        try await router.models()
    }

    /// Returns a verification that is valid now of a replica serving model,
    /// verifying replicas only if needed.
    @discardableResult
    public func ensureVerified(model: String) async throws -> Verification {
        try await router.ensureVerified(model: model)
    }

    /// The last successful verification of each replica used so far, without
    /// checking them. They may have expired or been rejected.
    public var current: [ReplicaVerification] {
        get async { await router.current }
    }

    /// Closes the client: later requests and verifications fail with
    /// `TinfoilError.configurationError`, from this client and from any
    /// OpenAI client built over it. Requests already sent finish. Closing
    /// again does nothing.
    public func close() async {
        await router.close()
    }

    /// Loads a request through the gateway, as `URLSession.data(for:)` does,
    /// sealed to a verified replica of the model the request names: in the
    /// `X-Tinfoil-Model` header, the `model` member of a JSON body, or the
    /// `model` field of a multipart upload. A URL without a host resolves
    /// against `baseURL`; an absolute URL must be on its origin. The body
    /// must be `httpBody`, not a stream.
    ///
    /// A replica that fails verification is skipped for the next replica of
    /// the model. If the gateway routes the request to another replica, that
    /// one is verified and the request sent again, sealed to it; so is the
    /// request after a rejected key, once. Cancelling the task before a
    /// resend prevents it.
    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let response = try await router.open(request)
        var data = Data()
        for try await chunk in response.body {
            data.append(chunk)
        }
        return (data, response.response)
    }

    /// Sends a request as `data(for:)` does, returning once the response
    /// headers arrive with the body still streaming and the request's session
    /// recovery token.
    public func recoverableBytes(for request: URLRequest) async throws -> RecoverableResponse {
        try await router.open(request)
    }

    /// Sends a request as `data(for:)` does, returning once the headers
    /// arrive. The OpenAI client's sessions send through it.
    func open(_ request: URLRequest) async throws -> (AsyncThrowingStream<Data, Error>, URLResponse) {
        let response = try await router.open(request)
        return (response.body, response.response)
    }
}
