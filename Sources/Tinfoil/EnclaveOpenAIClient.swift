import Foundation

/// An OpenAI client whose requests are sealed with EHBP to one attested
/// enclave that you name, matching tinfoil-go's `EnclaveOpenAIClient`. It
/// sends through an `EnclaveHTTPClient`, which is verified before the client
/// is returned.
public final class EnclaveOpenAIClient: OpenAICompatibleClient, Sendable {
    public let openAI: OpenAI
    /// The enclave client requests go through
    public let httpClient: EnclaveHTTPClient

    /// Creates an `EnclaveHTTPClient` for `enclave` using EHBP, verified as
    /// `EnclaveHTTPClient.init(enclave:repo:…)` verifies it, and an OpenAI
    /// client over it, as tinfoil-go's `NewEnclaveOpenAIClient` does. The API
    /// key is checked before any network I/O.
    ///
    /// The enclave parameters are those of `EnclaveHTTPClient`, which
    /// describes them; requests are always sealed with EHBP.
    /// - Parameters:
    ///   - apiKey: The API key; when nil, `TINFOIL_API_KEY` is read
    ///   - apiKeyProvider: Supplies the API key for each request, as for a
    ///     rotating token
    ///   - parsingOptions: Parsing options for handling different providers
    ///   - customHeaders: Headers to send on every request, merged over those
    ///     `tinfoilEvents` adds; caller values win
    ///   - tinfoilEvents: Tinfoil progress events to ask the router for, as
    ///     values of the `X-Tinfoil-Events` header
    public convenience init(
        enclave: String,
        repo: String,
        baseURL: URL? = nil,
        attestationRelay: String? = nil,
        policy: VerificationPolicy = VerificationPolicy(),
        userCacheSecret: String? = nil,
        onEnclaveVerified: EnclaveVerifiedCallback? = nil,
        onVerificationResult: VerificationResultCallback? = nil,
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        tinfoilEvents: Set<TinfoilEvent> = []
    ) async throws {
        let staticApiKey = try OpenAI.apiKey(apiKey, provider: apiKeyProvider)
        let httpClient = try await EnclaveHTTPClient(
            enclave: enclave,
            repo: repo,
            transportMode: .ehbp,
            baseURL: baseURL,
            attestationRelay: attestationRelay,
            policy: policy,
            userCacheSecret: userCacheSecret,
            onEnclaveVerified: onEnclaveVerified,
            onVerificationResult: onVerificationResult
        )
        try self.init(
            httpClient: httpClient,
            apiKey: staticApiKey,
            apiKeyProvider: apiKeyProvider,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            tinfoilEvents: tinfoilEvents
        )
    }

    /// Creates an OpenAI client that sends through `httpClient`, which must
    /// use `TransportMode.ehbp`. It does no network I/O: the client was
    /// verified when it was created. See `init(enclave:repo:…)` for the other
    /// parameters.
    public init(
        httpClient: EnclaveHTTPClient,
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        tinfoilEvents: Set<TinfoilEvent> = []
    ) throws {
        self.openAI = try OpenAI.sealed(
            apiKey: OpenAI.apiKey(apiKey, provider: apiKeyProvider),
            apiKeyProvider: apiKeyProvider,
            connection: httpClient.connection,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            tinfoilEvents: tinfoilEvents
        )
        self.httpClient = httpClient
    }
}
