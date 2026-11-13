import Foundation

/// An OpenAI client whose requests go through Tinfoil's gateway, each sealed
/// with EHBP to a verified replica of the model it names. It sends through a
/// `GatewayHTTPClient`. Only requests that name a model can be routed, so
/// methods without one, such as `models()` or the assistants and files
/// endpoints, fail with `TinfoilError.configurationError`; for the models the
/// gateway serves, use `httpClient.models()`.
///
/// Experimental: the gateway route is new, and this API may change or be
/// removed in a later release.
public final class GatewayOpenAIClient: OpenAICompatibleClient, Sendable {
    public let openAI: OpenAI
    /// The gateway client requests go through
    public let httpClient: GatewayHTTPClient

    /// Closes `httpClient`: later requests and verifications fail with
    /// `TinfoilError.configurationError`, from this client and any other over
    /// the same HTTP client. Requests already sent finish. Closing again does
    /// nothing.
    public func close() async {
        await httpClient.close()
    }

    /// Creates a `GatewayHTTPClient`, fetching the catalog as
    /// `GatewayHTTPClient.init(…)` does, and an OpenAI client over it. The
    /// API key is checked before any network I/O.
    ///
    /// The gateway parameters are those of `GatewayHTTPClient`, and the
    /// OpenAI parameters those of `EnclaveOpenAIClient`, which describe them.
    public convenience init(
        modelPins: [String: ModelPin] = [:],
        pinnedModelsOnly: Bool = false,
        baseURL: URL? = nil,
        verifier: Verifier? = nil,
        userCacheSecret: String? = nil,
        verificationCheck: VerificationCheck? = nil,
        onVerificationResult: VerificationResultCallback? = nil,
        catalog: (@Sendable () -> Catalog)? = nil,
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        timeoutInterval: TimeInterval = 60,
        tinfoilEvents: Set<TinfoilEvent> = []
    ) async throws {
        let staticApiKey = try OpenAI.apiKey(apiKey, provider: apiKeyProvider)
        let httpClient = try await GatewayHTTPClient(
            modelPins: modelPins,
            pinnedModelsOnly: pinnedModelsOnly,
            baseURL: baseURL,
            verifier: verifier,
            userCacheSecret: userCacheSecret,
            verificationCheck: verificationCheck,
            onVerificationResult: onVerificationResult,
            catalog: catalog
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

    /// Creates an OpenAI client that sends through `httpClient`. It does no
    /// network I/O: replicas are verified on each model's first request.
    public init(
        httpClient: GatewayHTTPClient,
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        timeoutInterval: TimeInterval = 60,
        tinfoilEvents: Set<TinfoilEvent> = []
    ) throws {
        self.openAI = try OpenAI.sealed(
            apiKey: OpenAI.apiKey(apiKey, provider: apiKeyProvider),
            apiKeyProvider: apiKeyProvider,
            baseURL: httpClient.baseURL.absoluteString,
            session: StreamingSession(delegate: nil, open: httpClient.open),
            streamingFactory: GatewaySessionFactory(httpClient: httpClient),
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            timeoutInterval: timeoutInterval,
            tinfoilEvents: tinfoilEvents
        )
        self.httpClient = httpClient
    }
}

/// Makes the OpenAI client's streaming sessions through the gateway, so a
/// streamed response arrives as the replica sends it.
final class GatewaySessionFactory: URLSessionFactory, Sendable {
    private let httpClient: GatewayHTTPClient

    init(httpClient: GatewayHTTPClient) {
        self.httpClient = httpClient
    }

    func makeUrlSession(delegate: URLSessionDataDelegateProtocol) -> URLSessionProtocol {
        StreamingSession(delegate: delegate, open: httpClient.open)
    }
}
