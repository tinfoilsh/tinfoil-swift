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
    public static let defaultURL = URL(string: "https://inference-gateway.tinfoil.sh/v1/")!

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
        let onVerification = options.onVerification
        let base = Self.directory(options.url ?? Self.defaultURL)
        try EnclaveConnection.validateBaseURL(base, transportMode: .ehbp)
        guard base.scheme?.lowercased() == "https" else {
            throw TinfoilError.configuration("invalid gateway URL: the gateway URL must use HTTPS")
        }
        guard let relay = Self.authority(of: base) else {
            throw TinfoilError.configuration("invalid gateway URL: the gateway URL has no host")
        }
        let attestor = { (policy: Policy) throws -> Attestor in
            Attestor(verifier: try GoAttestationVerifier(trust: nil, policy: policy), verificationCheck: verificationCheck)
        }
        let policy = try GatewayPolicy(
            pins: options.modelPins.mapValues { pin in (repo: pin.repo, attestor: try pin.policy.map { try attestor($0) }) },
            pinnedOnly: options.pinnedModelsOnly,
            attestor: attestor(options.policy)
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
                        onVerification: onVerification,
                        requiresHPKEKey: true
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

    /// The gateway's URL, which requests are sent to: the `url` option, with
    /// a trailing slash on its path, or Tinfoil's gateway. Relative URLs
    /// passed to `data(for:)` resolve against it.
    public var baseURL: URL { router.baseURL }

    /// The catalog's models that the client's policy serves, sorted, without
    /// verifying replicas. A failed catalog refresh doesn't fail it; only the
    /// first fetch can.
    public func models() async throws -> [String] {
        try await router.models()
    }

    /// Returns the report of a verification that is valid now of a replica
    /// serving model, verifying replicas only if needed.
    @discardableResult
    public func ensureVerified(model: String) async throws -> VerificationReport {
        try await router.ensureVerified(model: model)
    }

    /// One entry for each replica that the client has tried to verify and
    /// whose attempt has finished, failed replicas included, without I/O,
    /// each holding that replica's last attempt: its report if the attempt passed, and otherwise its
    /// error, as `EnclaveHTTPClient.lastVerification` describes. A replica's
    /// earlier success is not kept once a later attempt for it fails.
    /// Reports may have expired or been discarded since; a discarded
    /// replica's next request verifies it again.
    public var lastVerification: [ReplicaVerification] {
        get async { await router.lastVerification }
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

/// Configures a `GatewayHTTPClient`. Every option is optional, and the
/// default value of each one selects its default.
///
/// Experimental: the gateway route is new, and this API may change or be
/// removed in a later release.
public struct GatewayOptions: Sendable {
    /// The gateway's URL, which requests are sent to; nil selects Tinfoil's
    /// gateway. It must be HTTPS, and is treated as a directory: a path
    /// without a trailing slash gets one. Request paths join under it, so a
    /// URL with credentials, a query or a fragment, even an empty one, is
    /// refused.
    public var url: URL?
    /// Pins models to repositories. With `pinnedModelsOnly`, only pinned
    /// models are served, which requires at least one pin.
    public var modelPins: [String: ModelPin]
    /// Serve only the pinned models
    public var pinnedModelsOnly: Bool
    /// The verification policy for unpinned models, and pinned ones without
    /// their own; the default policy keeps every default
    public var policy: Policy
    /// The default prompt-cache scope of the client's requests; nil or empty
    /// uses a random secret that is generated once per process and that its
    /// clients share, so cache hits aren't shared across processes; pass one
    /// to keep it stable. A non-empty `user_cache_secret` string in a
    /// request's JSON body overrides it, so that a server can scope the cache
    /// to each end user. In a request with an `application/json` object body,
    /// the secret is replaced by a salt derived from it and the API key; any
    /// other body is sent as written, sealed to the verified replica. Use an
    /// opaque random value, not a raw user ID or API key: the gateway sees a
    /// cache prefix keyed on it, and could test guesses of a guessable secret
    /// and then of the prompt.
    public var userCacheSecret: String?
    /// Called with each replica's verified facts, for pinned and unpinned
    /// models, before its keys are used; throw to reject it, and the next
    /// replica of the model is tried.
    public var verificationCheck: VerificationCheck?
    /// Called once for every attempt to verify a replica, with the replica's
    /// host and the attempt's report or error. It only observes.
    /// `VerificationCallback` describes when it runs.
    public var onVerification: VerificationCallback?
    /// Read on every request in place of the gateway's catalog. Nil fetches
    /// the gateway's catalog when the client is created and refreshes it every
    /// 10 seconds while the client is used; a failed refresh keeps the last
    /// catalog that was fetched.
    public var catalog: (@Sendable () -> Catalog)?

    public init(
        modelPins: [String: ModelPin] = [:],
        pinnedModelsOnly: Bool = false,
        url: URL? = nil,
        policy: Policy = Policy(),
        userCacheSecret: String? = nil,
        verificationCheck: VerificationCheck? = nil,
        onVerification: VerificationCallback? = nil,
        catalog: (@Sendable () -> Catalog)? = nil
    ) {
        self.url = url
        self.modelPins = modelPins
        self.pinnedModelsOnly = pinnedModelsOnly
        self.policy = policy
        self.userCacheSecret = userCacheSecret
        self.verificationCheck = verificationCheck
        self.onVerification = onVerification
        self.catalog = catalog
    }
}
