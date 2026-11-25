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
    /// Tinfoil's gateway, at its origin. The OpenAI client adds the API
    /// path, `/v1/` by default, under it.
    public static let defaultURL = URL(string: "https://inference-gateway.tinfoil.sh/")!

    let router: GatewayRouter

    /// Creates a client and fetches the gateway's catalog, so that an
    /// unreachable gateway fails here rather than on the first request. The
    /// configuration is checked before any network I/O. A model's replicas
    /// are verified on its first request, so creating the client doesn't
    /// check that the catalog lists the pinned models; a request for a model
    /// that the catalog doesn't list fails. Without a non-empty
    /// `userCacheSecret`, the client uses the secret that is generated once
    /// per process; when it can't be generated, this throws
    /// `SecureRandomError`, before any network I/O.
    ///
    /// - Parameter options: The client's options; each one's default applies
    ///   when it is not set
    public convenience init(options: GatewayOptions) async throws {
        try await self.init(options: options, get: nil, verifier: { try GoAttestationVerifier(trust: nil, policy: $0) })
    }

    /// - Parameters:
    ///   - get: Fetches the catalog and the replicas' attestation documents;
    ///     nil fetches them over the network
    ///   - verifier: The verifier for a policy
    ///   - processSecret: The process's secret, which is used when
    ///     `userCacheSecret` is unset or empty
    convenience init(
        options: GatewayOptions,
        get: (@Sendable (URL) async throws -> Data)?,
        verifier: @escaping (Policy) throws -> any AttestationVerifier,
        processSecret: UserCacheSecret.ProcessSecret = UserCacheSecret.processSecret
    ) async throws {
        let verificationCheck = options.verificationCheck
        let onVerificationAttempt = options.onVerificationAttempt
        let base = Self.directory(options.url ?? Self.defaultURL)
        try EnclaveConnection.validateBaseURL(base, transportMode: .ehbp)
        guard base.scheme?.lowercased() == "https" else {
            throw TinfoilError.configuration("invalid gateway URL: the gateway URL must use HTTPS")
        }
        guard let catalogURL = URL(string: joined(base, path: "catalog")) else {
            throw TinfoilError.configuration("invalid gateway URL: cannot form the catalog URL under \(base.absoluteString)")
        }
        let secret = try UserCacheSecret.resolve(explicit: options.userCacheSecret, process: processSecret)
        // Attestation documents are relayed through the gateway, under the
        // URL that it is mounted at.
        let relay = AttestationFetcher.relay(base, get: get ?? { try await DocumentFetcher().fetch($0) })
        let attestor = { (policy: Policy) throws -> Attestor in
            Attestor(verifier: try verifier(policy), verificationCheck: verificationCheck, fetchAttestation: relay)
        }
        let policy = try GatewayPolicy(
            pins: options.modelPins.mapValues { pin in (repo: pin.repo, attestor: try pin.policy.map { try attestor($0) }) },
            attestor: attestor(options.policy)
        )
        let source: @Sendable () async throws -> Catalog
        if let catalog = options.catalog {
            source = { catalog() }
        } else {
            let cache = CatalogCache(fetch: {
                if let get {
                    return try await GatewayCatalog.fetch(url: catalogURL, fetch: get)
                }
                return try await GatewayCatalog.fetch(url: catalogURL)
            })
            source = { try await cache.get() }
        }
        try await self.init(router: GatewayRouter(
            baseURL: base,
            policy: policy,
            catalog: source,
            secret: secret,
            makeReplica: { replica, attestor in
                let pin = GatewayCatalog.pin(replica.reference)
                try attestor.checkPinVerifiability(pin)
                return try EnclaveConnection(
                    handle: EnclaveHandle(
                        enclave: replica.host,
                        pin: pin,
                        attestationRelay: nil,
                        attestor: attestor,
                        onVerificationAttempt: onVerificationAttempt,
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
    /// a trailing slash on its path, or Tinfoil's gateway. It is the
    /// gateway's origin, or the URL that the gateway is mounted under, never
    /// the API path: relative URLs passed to `data(for:)` resolve against
    /// it, so name the API path in them, as in `v1/chat/completions`.
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

    /// Verifies again the replica that `ensureVerified(model:)` would
    /// return, even if its cached verification is still valid, and returns
    /// the new report. It tries the model's replicas in the order that
    /// `ensureVerified(model:)` tries them, verifying each again, and stops
    /// at the first that passes, or that fails but keeps a valid
    /// verification, which requests for model still use; it then throws that
    /// failure. Each failure follows the rule that
    /// `EnclaveHTTPClient.reverify()` describes, for its replica: a
    /// `TinfoilError.attestationError` discards the replica's cached
    /// verification, so that `reverify(model:)` moves on to the next replica,
    /// as `ensureVerified(model:)` then does, and a failure of any other
    /// category keeps it while it is still valid. When no replica passes or
    /// keeps a valid verification, it throws the last failure. A model that
    /// isn't pinned fails with `TinfoilError.configurationError`, and no
    /// replica is verified.
    @discardableResult
    public func reverify(model: String) async throws -> VerificationReport {
        try await router.reverify(model: model)
    }

    /// One entry for each replica that the client has tried to verify and
    /// whose attempt has finished, failed replicas included, sorted by host,
    /// without I/O. An entry's `current` follows the rule of
    /// `EnclaveHTTPClient.currentVerification` for that replica: the report
    /// of the replica's verification while it is fresh and has not been
    /// discarded, and otherwise nil. Its `lastAttempt` holds the replica's
    /// most recent attempt, as `EnclaveHTTPClient.lastVerificationAttempt`
    /// describes: a failed attempt replaces an earlier success there, though
    /// `current` keeps that success while the failure leaves it valid. A
    /// discarded replica's next request verifies it again.
    public var replicas: [ReplicaVerification] {
        get async { await router.replicaVerifications }
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

/// Configures a `GatewayHTTPClient`. Every option but `modelPins` is
/// optional, and the default value of each one selects its default.
///
/// Experimental: the gateway route is new, and this API may change or be
/// removed in a later release.
public struct GatewayOptions: Sendable {
    /// The gateway's URL, which requests are sent to; nil selects Tinfoil's
    /// gateway, `https://inference-gateway.tinfoil.sh/`. It is the gateway's
    /// origin, or the URL that the gateway is mounted under, not the API
    /// path: the catalog (`{url}/catalog`), the attestation relay
    /// (`{url}/.well-known/tinfoil-attestation`) and an `OpenAIClient`'s API
    /// path join under it, whether or not it ends with a slash. It must be
    /// HTTPS, and is treated as a directory: a path without a trailing slash
    /// gets one. Request paths join under it, so a URL with credentials, a
    /// query or a fragment, even an empty one, is refused.
    public var url: URL?
    /// Pins models to repositories. The client serves only the models that
    /// it has pins for, so at least one pin is required, and a request for
    /// any other model fails with `TinfoilError.configurationError` without
    /// contacting a replica.
    public var modelPins: [String: ModelPin]
    /// The verification policy for pins that set none; a pin's own policy
    /// replaces it entirely. It is checked when the client is created even
    /// if every pin sets its own. The default policy keeps every default.
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
    /// Called with each replica's verified facts before its keys are used;
    /// throw to reject it, and the next
    /// replica of the model is tried.
    public var verificationCheck: VerificationCheck?
    /// Called once for every attempt to verify a replica, failed attempts
    /// included, with the replica's host and the attempt's report or error.
    /// It only observes. `VerificationCallback` describes when it runs.
    public var onVerificationAttempt: VerificationCallback?
    /// Read on every request in place of the gateway's catalog. Nil fetches
    /// the gateway's catalog when the client is created and refreshes it every
    /// 10 seconds while the client is used; a failed refresh keeps the last
    /// catalog that was fetched.
    public var catalog: (@Sendable () -> Catalog)?

    public init(
        modelPins: [String: ModelPin],
        url: URL? = nil,
        policy: Policy = Policy(),
        userCacheSecret: String? = nil,
        verificationCheck: VerificationCheck? = nil,
        onVerificationAttempt: VerificationCallback? = nil,
        catalog: (@Sendable () -> Catalog)? = nil
    ) {
        self.url = url
        self.modelPins = modelPins
        self.policy = policy
        self.userCacheSecret = userCacheSecret
        self.verificationCheck = verificationCheck
        self.onVerificationAttempt = onVerificationAttempt
        self.catalog = catalog
    }
}
