import Foundation

/// An OpenAI client whose requests reach one of Tinfoil's verified routers,
/// over pinned TLS by default or sealed with EHBP. It sends through a
/// `RouterHTTPClient`, which picks and verifies a router before the client is
/// returned.
///
/// It exists only while the router is Tinfoil's default route. For inference
/// that doesn't depend on the route, use `Client`.
public final class RouterOpenAIClient: OpenAICompatibleClient, Sendable {
    public let openAI: OpenAI
    /// The router client requests go through
    public let httpClient: RouterHTTPClient

    /// Closes `httpClient`: later requests and verifications fail with
    /// `TinfoilError.configurationError`, from this client and any other over
    /// the same HTTP client. Requests already sent finish. Closing again does
    /// nothing.
    public func close() async {
        await httpClient.close()
    }

    /// Creates a `RouterHTTPClient`, picking and verifying a router as
    /// `RouterHTTPClient.init(…)` does, and an OpenAI client over it. The API
    /// key is checked before any network I/O.
    ///
    /// The router parameters, `transportMode` included, are those of
    /// `RouterHTTPClient`, and the OpenAI parameters those of
    /// `EnclaveOpenAIClient`, which describe them.
    public convenience init(
        transportMode: TransportMode = .tls,
        baseURL: URL? = nil,
        attestationRelay: String? = nil,
        verifier: Verifier? = nil,
        userCacheSecret: String? = nil,
        verificationCheck: VerificationCheck? = nil,
        onVerificationResult: VerificationResultCallback? = nil,
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        timeoutInterval: TimeInterval = 60,
        tinfoilEvents: Set<TinfoilEvent> = []
    ) async throws {
        let staticApiKey = try OpenAI.apiKey(apiKey, provider: apiKeyProvider)
        let httpClient = try await RouterHTTPClient(
            transportMode: transportMode,
            baseURL: baseURL,
            attestationRelay: attestationRelay,
            verifier: verifier,
            userCacheSecret: userCacheSecret,
            verificationCheck: verificationCheck,
            onVerificationResult: onVerificationResult
        )
        try self.init(
            httpClient: httpClient,
            apiKey: staticApiKey,
            apiKeyProvider: apiKeyProvider,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            timeoutInterval: timeoutInterval,
            tinfoilEvents: tinfoilEvents
        )
    }

    /// Creates an OpenAI client that sends through `httpClient`, in its
    /// transport mode. It does no network I/O: the client was
    /// verified when it was created.
    public init(
        httpClient: RouterHTTPClient,
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        timeoutInterval: TimeInterval = 60,
        tinfoilEvents: Set<TinfoilEvent> = []
    ) throws {
        self.openAI = try OpenAI.attested(
            apiKey: OpenAI.apiKey(apiKey, provider: apiKeyProvider),
            apiKeyProvider: apiKeyProvider,
            connection: httpClient.connection,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            timeoutInterval: timeoutInterval,
            tinfoilEvents: tinfoilEvents
        )
        self.httpClient = httpClient
    }
}
