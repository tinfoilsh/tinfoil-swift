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
/// that doesn't depend on the route, use `Client`.
public final class RouterHTTPClient: Sendable {
    let connection: EnclaveConnection

    /// Picks the first of Tinfoil's routers that verifies, and otherwise the
    /// fallback router, and verifies it. Routers are tried for at most 30
    /// seconds before falling back, and each call discovers again. With an
    /// attestation relay, the relay is asked for the fallback router instead.
    /// The configuration is checked before any network I/O.
    ///
    /// - Parameter options: The client's options; each one's default applies
    ///   when it is not set
    public convenience init(options: RouterOptions = RouterOptions()) async throws {
        try await self.init(verifying: EnclaveConnection.router(
            attestor: Attestor(
                verifier: try (options.verifier ?? Verifier()).backend(trust: nil),
                verificationCheck: options.verificationCheck
            ),
            transportMode: options.transport.mode,
            baseURL: options.transport.proxyURL,
            attestationRelay: options.attestationRelay,
            userCacheSecret: options.userCacheSecret,
            onVerificationResult: options.onVerificationResult
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

    /// Verifies the router again, even if the cached verification is still
    /// valid. It stays with the router chosen at creation.
    @discardableResult
    public func reverify() async throws -> Verification {
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
