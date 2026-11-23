import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A client for one of Tinfoil's routers, which forwards requests to the
/// enclaves serving each model. It picks and verifies a router before its
/// initializer returns, then sends only to that router, verifying it again
/// once the verification expires or the router rejects its key.
///
/// It exists only while the router is Tinfoil's default route. For inference
/// that doesn't depend on the route, use `OpenAIClient(apiKey:…)`.
public final class RouterHTTPClient: Sendable {
    let connection: EnclaveConnection

    /// Picks the first router of the list, in a random order, that verifies,
    /// and otherwise the fallback router, and verifies it. Routers are tried
    /// for at most 30 seconds before falling back, and each call discovers
    /// again, whatever the options. The configuration is checked before any
    /// network I/O.
    ///
    /// - Parameter options: The client's options; each one's default applies
    ///   when it is not set
    public convenience init(options: RouterOptions = RouterOptions()) async throws {
        try options.fetchAttestation?.relayURL.map { try EnclaveConnection.validateRelayURL($0) }
        try options.fetchRouterList?.relayURL.map { try EnclaveConnection.validateRelayURL($0) }
        try await self.init(verifying: EnclaveConnection.router(
            attestor: Attestor(
                verifier: try GoAttestationVerifier(trust: nil, policy: options.policy),
                verificationCheck: options.verificationCheck,
                fetchAttestation: options.fetchAttestation,
                fetchRouterList: options.fetchRouterList
            ),
            transportMode: options.transport.mode,
            baseURL: options.transport.proxyURL,
            userCacheSecret: options.userCacheSecret,
            onVerification: options.onVerification
        ))
    }

    /// Verifies connection before the client is handed out. Discovery leaves
    /// its fallback router unverified, so this verifies it.
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
    public var transport: Transport { connection.transport }

    /// The URL that requests are sent to: the EHBP proxy URL, or the
    /// router's own origin when the client connects directly. Relative URLs
    /// passed to `data(for:)` resolve against it.
    public var baseURL: URL { connection.baseURL }

    /// The host of the router the client chose. It stays the router's host
    /// when requests go through a proxy.
    public var enclave: String { connection.enclave }

    /// The outcome of the client's most recent attempt to verify the router
    /// that it chose, without I/O, or nil before the first: the attempt's
    /// report if it passed, and otherwise the error that the client reported
    /// for it.
    /// When the verifier rejected the document, the error is
    /// `TinfoilError.attestationError`, whose `verificationError` carries the
    /// report that shows the step that failed; an attempt that failed before
    /// the verifier ran, such as a failed fetch, or that the
    /// `verificationCheck` rejected, has none. Every attempt counts: the first
    /// verification, retries, and every verification again, so a failure
    /// replaces an earlier success.
    ///
    /// It doesn't check freshness, so a report that it returns may have
    /// expired or been discarded since; use `ensureVerified()` for one that
    /// is valid now.
    public var lastVerification: Result<VerificationReport, TinfoilError>? {
        get async { await connection.lastVerification }
    }

    /// Returns the report of a verification that is valid now, verifying
    /// first only if the cached one has expired. A returned report means
    /// requests can be sent.
    @discardableResult
    public func ensureVerified() async throws -> VerificationReport {
        try await connection.ensureVerified()
    }

    /// Verifies the router again, even if the cached verification is still
    /// valid. It stays with the router chosen at creation.
    ///
    /// If the new verification fails with `TinfoilError.attestationError`,
    /// this throws it and the client discards its cached verification, even
    /// one that is still valid: no later request is sent under it, and the
    /// next request verifies again, failing while the problem persists.
    /// Other failures, such as a `TinfoilError.networkError` or a
    /// cancellation, keep a cached verification that is still valid.
    /// Requests already in flight finish. Either way, the failed attempt
    /// becomes `lastVerification`. It returns the new report. Cancelling the
    /// call ends only its own wait: the verification that it started or
    /// joined still finishes, and its outcome becomes `lastVerification`.
    @discardableResult
    public func reverify() async throws -> VerificationReport {
        try await connection.reverify()
    }

    /// Loads a request from the router, as `URLSession.data(for:)` does. See
    /// `EnclaveHTTPClient.data(for:)`; the same rules apply.
    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await connection.data(for: request)
    }

    /// Loads a URL from the router, as `URLSession.data(from:)` does.
    public func data(from url: URL) async throws -> (Data, HTTPURLResponse) {
        try await connection.data(from: url)
    }

    /// Sends a request to the router and returns its response with the body
    /// still streaming and its session recovery token. See
    /// `EnclaveHTTPClient.recoverableBytes(for:)`; the same rules apply.
    public func recoverableBytes(for request: URLRequest) async throws -> RecoverableResponse {
        try await connection.recoverableBytes(for: request)
    }
}
