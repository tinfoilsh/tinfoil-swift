import Foundation

/// An OpenAI client whose requests reach only one attested enclave that you
/// name, over pinned TLS by default or sealed with EHBP. It sends through an
/// `EnclaveHTTPClient`, which is verified before the client is returned.
public final class EnclaveOpenAIClient: OpenAICompatibleClient, Sendable {
    public let openAI: OpenAI
    /// The enclave client requests go through
    public let httpClient: EnclaveHTTPClient

    /// Closes `httpClient`: later requests and verifications fail with
    /// `TinfoilError.configurationError`, from this client and any other over
    /// the same HTTP client. Requests already sent finish. Closing again does
    /// nothing.
    public func close() async {
        await httpClient.close()
    }

    /// Creates an `EnclaveHTTPClient` for `enclave`, verified as
    /// `EnclaveHTTPClient.init(enclave:trust:options:)` verifies it, and an OpenAI
    /// client over it. The API key is checked before any network I/O.
    ///
    /// `enclave`, `trust` and `options` are those of `EnclaveHTTPClient`, which
    /// describes them.
    /// - Parameters:
    ///   - apiKey: The API key; required unless `apiKeyProvider` is given
    ///   - apiKeyProvider: Supplies the API key for each request, as for a
    ///     rotating token
    ///   - parsingOptions: Parsing options for handling different providers
    ///   - customHeaders: Headers to send on every request, merged over those
    ///     `tinfoilEvents` adds; caller values win
    ///   - timeoutInterval: How long a request may wait for the next bytes
    ///     of its response before it fails, in seconds; 60 by default. Raise
    ///     it for long completions that send nothing until they finish.
    ///   - tinfoilEvents: Tinfoil progress events to ask the router for, as
    ///     values of the `X-Tinfoil-Events` header
    public convenience init(
        enclave: String,
        trust: Trust,
        options: EnclaveOptions = EnclaveOptions(),
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        timeoutInterval: TimeInterval = 60,
        tinfoilEvents: Set<TinfoilEvent> = []
    ) async throws {
        let staticApiKey = try OpenAI.apiKey(apiKey, provider: apiKeyProvider)
        let httpClient = try await EnclaveHTTPClient(
            enclave: enclave,
            trust: trust,
            options: options
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
    /// verified when it was created. See `init(enclave:trust:options:…)` for the other
    /// parameters.
    public init(
        httpClient: EnclaveHTTPClient,
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
