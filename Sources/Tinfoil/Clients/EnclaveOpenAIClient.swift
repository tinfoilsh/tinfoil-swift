import Foundation

/// An OpenAI client whose requests reach only one attested enclave that you
/// name, over pinned TLS by default or sealed with EHBP. It sends through an
/// `EnclaveHTTPClient`, which is verified before the client is returned.
public final class EnclaveOpenAIClient: OpenAICompatibleClient, Sendable {
    public let openAI: OpenAI
    /// The enclave client requests go through
    public let httpClient: EnclaveHTTPClient

    /// Creates an `EnclaveHTTPClient` for `enclave`, verified as
    /// `EnclaveHTTPClient.init(enclave:repo:…)` verifies it, and an OpenAI
    /// client over it. The API key is checked before any network I/O.
    ///
    /// The enclave parameters, `transportMode` included, are those of
    /// `EnclaveHTTPClient`, which describes them. Pinned TLS protects whole
    /// requests and needs a direct connection; EHBP seals bodies, so they stay
    /// private through a proxy `baseURL`.
    /// - Parameters:
    ///   - apiKey: The API key; required unless `apiKeyProvider` is given
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
        tinfoilEvents: Set<TinfoilEvent> = []
    ) async throws {
        let staticApiKey = try OpenAI.apiKey(apiKey, provider: apiKeyProvider)
        let httpClient = try await EnclaveHTTPClient(
            enclave: enclave,
            repo: repo,
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
            tinfoilEvents: tinfoilEvents
        )
    }

    /// Creates an OpenAI client that sends through `httpClient`, in its
    /// transport mode. It does no network I/O: the client was
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
        self.openAI = try OpenAI.attested(
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
