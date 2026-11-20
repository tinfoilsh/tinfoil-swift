import Foundation

/// Configures an `EnclaveHTTPClient`. Every option is optional, and the
/// default value of each one selects its default.
public struct EnclaveOptions: Sendable {
    /// How requests are protected: pinned TLS by default, or EHBP, directly
    /// or through a proxy
    public var transport: Transport
    /// The verification policy that applies on top of the client's trust;
    /// the default policy keeps every default
    public var policy: Policy
    /// Called each time the enclave's evidence verifies, before its keys are
    /// used; throw to reject it.
    public var verificationCheck: VerificationCheck?
    /// How the enclave's attestation documents are obtained, for every
    /// verification; nil fetches them directly from the enclave. Use
    /// `.relay(_:)` to fetch them through a relay.
    public var fetchAttestation: AttestationFetcher?
    /// Called with each verification's final result. It only observes.
    public var onVerificationResult: VerificationResultCallback?

    public init(
        transport: Transport = .tls,
        policy: Policy = Policy(),
        verificationCheck: VerificationCheck? = nil,
        fetchAttestation: AttestationFetcher? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) {
        self.transport = transport
        self.policy = policy
        self.verificationCheck = verificationCheck
        self.fetchAttestation = fetchAttestation
        self.onVerificationResult = onVerificationResult
    }
}

/// Configures a `RouterHTTPClient`. Every option is optional, and the default
/// value of each one selects its default.
public struct RouterOptions: Sendable {
    /// How requests are protected: pinned TLS by default, or EHBP, directly
    /// or through a proxy that forwards requests to the router that discovery
    /// chooses
    public var transport: Transport
    /// The verification policy that applies on top of the client's trust;
    /// the default policy keeps every default
    public var policy: Policy
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
    /// How routers' attestation documents are obtained: for each router that
    /// discovery tries, for the fallback router, and for every later
    /// verification; nil fetches them directly from each router. Use
    /// `.relay(_:)` to fetch them through a relay.
    public var fetchAttestation: AttestationFetcher?
    /// How the list of candidate routers is obtained; nil fetches Tinfoil's,
    /// from `https://atc.tinfoil.sh/routers`. Use `.relay(_:)` to fetch it
    /// through a relay. Discovery runs whichever list it gets.
    public var fetchRouterList: RouterListFetcher?
    /// Called with each verification's final result. It only observes.
    public var onVerificationResult: VerificationResultCallback?

    public init(
        transport: Transport = .tls,
        policy: Policy = Policy(),
        userCacheSecret: String? = nil,
        verificationCheck: VerificationCheck? = nil,
        fetchAttestation: AttestationFetcher? = nil,
        fetchRouterList: RouterListFetcher? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) {
        self.transport = transport
        self.policy = policy
        self.userCacheSecret = userCacheSecret
        self.verificationCheck = verificationCheck
        self.fetchAttestation = fetchAttestation
        self.fetchRouterList = fetchRouterList
        self.onVerificationResult = onVerificationResult
    }
}
