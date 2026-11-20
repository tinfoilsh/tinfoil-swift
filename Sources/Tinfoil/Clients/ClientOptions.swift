import Foundation

/// Configures an `EnclaveHTTPClient`. Every option is optional, and the
/// default value of each one selects its default.
public struct EnclaveOptions: Sendable {
    /// How requests are protected; pinned TLS by default
    public var transportMode: TransportMode
    /// Where requests are sent: a path on the enclave's own origin, or a
    /// proxy on another origin, which requires `.ehbp`. Requests to a proxy
    /// carry `X-Tinfoil-Enclave-Url` so that it can forward them to the
    /// enclave. It must be HTTPS, since EHBP doesn't seal headers such as the
    /// API key; under `.ehbp`, `http` is also accepted when the host is
    /// `localhost` or a loopback IP address, as for a local development proxy
    /// or a sidecar.
    public var baseURL: URL?
    /// The trust policy; nil selects the defaults
    public var verifier: Verifier?
    /// Scopes the prompt cache of the client's requests. Only Tinfoil's
    /// router reads it, so it is sent only when set. A non-empty
    /// `user_cache_secret` string in a request's JSON body overrides it. Use
    /// an opaque random value, not a raw user ID or API key.
    public var userCacheSecret: String?
    /// Called each time the enclave's evidence verifies, before its keys are
    /// used; throw to reject it.
    public var verificationCheck: VerificationCheck?
    /// Host, with an optional port, that forwards attestation requests to the
    /// enclave
    public var attestationRelay: String?
    /// Called with each verification's final result. It only observes.
    public var onVerificationResult: VerificationResultCallback?

    public init(
        transportMode: TransportMode = .tls,
        baseURL: URL? = nil,
        attestationRelay: String? = nil,
        verifier: Verifier? = nil,
        userCacheSecret: String? = nil,
        verificationCheck: VerificationCheck? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) {
        self.transportMode = transportMode
        self.baseURL = baseURL
        self.verifier = verifier
        self.userCacheSecret = userCacheSecret
        self.verificationCheck = verificationCheck
        self.attestationRelay = attestationRelay
        self.onVerificationResult = onVerificationResult
    }
}

/// Configures a `RouterHTTPClient`. Every option is optional, and the default
/// value of each one selects its default.
public struct RouterOptions: Sendable {
    /// How requests are protected; pinned TLS by default
    public var transportMode: TransportMode
    /// A proxy that requests are sent to, which requires `.ehbp` because the
    /// router's origin isn't known before discovery. Requests carry
    /// `X-Tinfoil-Enclave-Url` so that it can forward them. It must be HTTPS,
    /// since EHBP doesn't seal headers such as the API key, or `http` when the
    /// host is `localhost` or a loopback IP address, as for a local
    /// development proxy or a sidecar.
    public var baseURL: URL?
    /// The trust policy; nil selects the defaults
    public var verifier: Verifier?
    /// Scopes the router's prompt cache for the client's requests. When
    /// unset, a random secret that is generated once per process and that its
    /// clients share is used, so cache hits aren't shared across processes;
    /// pass one to keep it stable. A non-empty `user_cache_secret` string in a
    /// request's JSON body overrides it. Use an opaque random value, not a raw
    /// user ID or API key.
    public var userCacheSecret: String?
    /// Called each time a router's evidence verifies, before its keys are
    /// used; throw to reject it, and discovery moves to the next router.
    public var verificationCheck: VerificationCheck?
    /// Host, with an optional port, that forwards attestation requests to the
    /// fallback router
    public var attestationRelay: String?
    /// Called with each verification's final result. It only observes.
    public var onVerificationResult: VerificationResultCallback?

    public init(
        transportMode: TransportMode = .tls,
        baseURL: URL? = nil,
        attestationRelay: String? = nil,
        verifier: Verifier? = nil,
        userCacheSecret: String? = nil,
        verificationCheck: VerificationCheck? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) {
        self.transportMode = transportMode
        self.baseURL = baseURL
        self.verifier = verifier
        self.userCacheSecret = userCacheSecret
        self.verificationCheck = verificationCheck
        self.attestationRelay = attestationRelay
        self.onVerificationResult = onVerificationResult
    }
}

/// Configures a `GatewayHTTPClient`. Every option is optional, and the
/// default value of each one selects its default.
///
/// Experimental: the gateway route is new, and this API may change or be
/// removed in a later release.
public struct GatewayOptions: Sendable {
    /// The gateway's base URL; nil selects Tinfoil's gateway. It must be
    /// HTTPS, and is treated as a directory: a path without a trailing slash
    /// gets one. Request paths join under it, so a URL with credentials, a
    /// query or a fragment, even an empty one, is refused.
    public var baseURL: URL?
    /// Pins models to repositories. With `pinnedModelsOnly`, only pinned
    /// models are served, which requires at least one pin.
    public var modelPins: [String: ModelPin]
    /// Serve only the pinned models
    public var pinnedModelsOnly: Bool
    /// The trust policy for unpinned models, and pinned ones without their
    /// own; nil selects the defaults. A policy whose config the caller
    /// supplies or approves is refused: replicas are verified against
    /// repositories.
    public var verifier: Verifier?
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
    /// Called with each replica's verification, for pinned and unpinned
    /// models, before its keys are used; throw to reject it, and the next
    /// replica of the model is tried.
    public var verificationCheck: VerificationCheck?
    /// Called with each replica verification's final result. It only
    /// observes.
    public var onVerificationResult: VerificationResultCallback?
    /// Read on every request in place of the gateway's catalog. Nil fetches
    /// the gateway's catalog when the client is created and refreshes it every
    /// 10 seconds while the client is used; a failed refresh keeps the last
    /// catalog that was fetched.
    public var catalog: (@Sendable () -> Catalog)?

    public init(
        modelPins: [String: ModelPin] = [:],
        pinnedModelsOnly: Bool = false,
        baseURL: URL? = nil,
        verifier: Verifier? = nil,
        userCacheSecret: String? = nil,
        verificationCheck: VerificationCheck? = nil,
        onVerificationResult: VerificationResultCallback? = nil,
        catalog: (@Sendable () -> Catalog)? = nil
    ) {
        self.baseURL = baseURL
        self.modelPins = modelPins
        self.pinnedModelsOnly = pinnedModelsOnly
        self.verifier = verifier
        self.userCacheSecret = userCacheSecret
        self.verificationCheck = verificationCheck
        self.onVerificationResult = onVerificationResult
        self.catalog = catalog
    }
}
