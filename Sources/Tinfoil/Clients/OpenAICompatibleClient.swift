import Foundation

/// An OpenAI-compatible client whose requests are sealed to a verified
/// enclave. `Client`, `EnclaveOpenAIClient` and `RouterOpenAIClient` share
/// its OpenAI methods, which pass through to `openAI`.
public protocol OpenAICompatibleClient {
    /// The OpenAI client every request goes through, built so its requests
    /// are sealed to the verified enclave. Use it for an OpenAI method the
    /// client doesn't offer itself.
    var openAI: OpenAI { get }
}

extension OpenAICompatibleClient {

    public func chats(query: ChatQuery) async throws -> ChatResult {
        try await openAI.chats(query: query)
    }

    /// Sends a chat completion with additional headers applied to this call
    /// only, on top of the client's `customHeaders`. Use this for values that
    /// change per request, such as a conversation id.
    public func chats(query: ChatQuery, headers: [String: String]) async throws -> ChatResult {
        try await openAI.chats(query: query, headers: headers)
    }

    public func chatsStream(query: ChatQuery) -> AsyncThrowingStream<ChatStreamResult, Error> {
        openAI.chatsStream(query: query)
    }

    /// Streams a chat completion with additional headers applied to this call
    /// only, on top of the client's `customHeaders`. Use this for values that
    /// change per request, such as a conversation id.
    public func chatsStream(query: ChatQuery, headers: [String: String]) -> AsyncThrowingStream<ChatStreamResult, Error> {
        openAI.chatsStream(query: query, headers: headers)
    }

    public func images(query: ImagesQuery) async throws -> ImagesResult {
        try await openAI.images(query: query)
    }

    public func imageEdits(query: ImageEditsQuery) async throws -> ImagesResult {
        try await openAI.imageEdits(query: query)
    }

    public func imageVariations(query: ImageVariationsQuery) async throws -> ImagesResult {
        try await openAI.imageVariations(query: query)
    }

    public func embeddings(query: EmbeddingsQuery) async throws -> EmbeddingsResult {
        try await openAI.embeddings(query: query)
    }

    public func model(query: ModelQuery) async throws -> ModelResult {
        try await openAI.model(query: query)
    }

    public func models() async throws -> ModelsResult {
        try await openAI.models()
    }

    public func moderations(query: ModerationsQuery) async throws -> ModerationsResult {
        try await openAI.moderations(query: query)
    }

    public func audioCreateSpeech(query: AudioSpeechQuery) async throws -> AudioSpeechResult {
        try await openAI.audioCreateSpeech(query: query)
    }

    public func audioCreateSpeechStream(query: AudioSpeechQuery) -> AsyncThrowingStream<AudioSpeechResult, Error> {
        openAI.audioCreateSpeechStream(query: query)
    }

    /// Streams EHBP-encrypted speech with response validation options, such as
    /// requiring `audio/pcm` before delivering bytes to a PCM player.
    public func audioCreateSpeechStream(query: AudioSpeechQuery, options: AudioSpeechStreamOptions) -> AsyncThrowingStream<AudioSpeechResult, Error> {
        openAI.audioCreateSpeechStream(query: query, options: options)
    }

    public func audioTranscriptions(query: AudioTranscriptionQuery) async throws -> AudioTranscriptionResult {
        try await openAI.audioTranscriptions(query: query)
    }

    public func audioTranscriptionsVerbose(query: AudioTranscriptionQuery) async throws -> AudioTranscriptionVerboseResult {
        try await openAI.audioTranscriptionsVerbose(query: query)
    }

    public func audioTranscriptionStream(query: AudioTranscriptionQuery) -> AsyncThrowingStream<AudioTranscriptionStreamResult, Error> {
        openAI.audioTranscriptionStream(query: query)
    }

    public func audioTranslations(query: AudioTranslationQuery) async throws -> AudioTranslationResult {
        try await openAI.audioTranslations(query: query)
    }

    public func assistants() async throws -> AssistantsResult {
        try await openAI.assistants()
    }

    public func assistants(after: String?) async throws -> AssistantsResult {
        try await openAI.assistants(after: after)
    }

    public func assistantCreate(query: AssistantsQuery) async throws -> AssistantResult {
        try await openAI.assistantCreate(query: query)
    }

    public func assistantModify(query: AssistantsQuery, assistantId: String) async throws -> AssistantResult {
        try await openAI.assistantModify(query: query, assistantId: assistantId)
    }

    public func threads(query: ThreadsQuery) async throws -> ThreadsResult {
        try await openAI.threads(query: query)
    }

    public func threadRun(query: ThreadRunQuery) async throws -> RunResult {
        try await openAI.threadRun(query: query)
    }

    public func runs(threadId: String, query: RunsQuery) async throws -> RunResult {
        try await openAI.runs(threadId: threadId, query: query)
    }

    public func runRetrieve(threadId: String, runId: String) async throws -> RunResult {
        try await openAI.runRetrieve(threadId: threadId, runId: runId)
    }

    public func runRetrieveSteps(threadId: String, runId: String) async throws -> RunRetrieveStepsResult {
        try await openAI.runRetrieveSteps(threadId: threadId, runId: runId)
    }

    public func runRetrieveSteps(threadId: String, runId: String, before: String?) async throws -> RunRetrieveStepsResult {
        try await openAI.runRetrieveSteps(threadId: threadId, runId: runId, before: before)
    }

    public func runSubmitToolOutputs(threadId: String, runId: String, query: RunToolOutputsQuery) async throws -> RunResult {
        try await openAI.runSubmitToolOutputs(threadId: threadId, runId: runId, query: query)
    }

    public func threadsMessages(threadId: String) async throws -> ThreadsMessagesResult {
        try await openAI.threadsMessages(threadId: threadId)
    }

    public func threadsMessages(threadId: String, before: String?) async throws -> ThreadsMessagesResult {
        try await openAI.threadsMessages(threadId: threadId, before: before)
    }

    public func threadsAddMessage(threadId: String, query: MessageQuery) async throws -> ThreadAddMessageResult {
        try await openAI.threadsAddMessage(threadId: threadId, query: query)
    }

    public func files(query: FilesQuery) async throws -> FilesResult {
        try await openAI.files(query: query)
    }

    // MARK: - Responses API

    public func createResponse(query: CreateModelResponseQuery) async throws -> ResponseObject {
        try await openAI.responses.createResponse(query: query)
    }

    public func createResponseStream(query: CreateModelResponseQuery) -> AsyncThrowingStream<ResponseStreamEvent, Error> {
        openAI.responses.createResponseStreaming(query: query)
    }
}

/// How the SDK's OpenAI-compatible clients build their `OpenAI` client
extension OpenAI {
    /// The static API key, required unless a provider can supply one.
    /// Attestation itself does not use the key; it only authorizes inference
    /// requests, so a caller using a rotating token (e.g. a short-lived JWT)
    /// is not forced to pass a placeholder key.
    static func apiKey(_ apiKey: String?, provider: (@Sendable () -> String?)?) throws -> String? {
        let staticApiKey = apiKey ?? ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        guard staticApiKey != nil || provider != nil else {
            throw TinfoilError.configuration("no API key was given; pass apiKey or apiKeyProvider, or set TINFOIL_API_KEY")
        }
        return staticApiKey
    }

    /// An OpenAI client over a verified connection's EHBP sessions, which
    /// every request body is sealed through.
    static func sealed(
        apiKey: String?,
        apiKeyProvider: (@Sendable () -> String?)?,
        connection: EnclaveConnection,
        parsingOptions: ParsingOptions,
        customHeaders: [String: String],
        tinfoilEvents: Set<TinfoilEvent>
    ) throws -> OpenAI {
        guard let ehbp = connection.ehbp else {
            throw TinfoilError.configuration("OpenAI requests are sealed with EHBP, so the HTTP client must use TransportMode.ehbp")
        }
        return try sealed(
            apiKey: apiKey,
            apiKeyProvider: apiKeyProvider,
            baseURL: connection.baseURL.absoluteString,
            session: ehbp.session,
            streamingFactory: ehbp.streamingFactory,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            tinfoilEvents: tinfoilEvents
        )
    }

    /// Sets up the OpenAI client over the given EHBP sessions. Requests go to
    /// `baseURL`, under its path if it has one, and under `/v1` for a bare
    /// origin.
    static func sealed(
        apiKey: String?,
        apiKeyProvider: (@Sendable () -> String?)?,
        baseURL: String,
        session: EHBPURLSession,
        streamingFactory: EHBPURLSessionFactory,
        parsingOptions: ParsingOptions,
        customHeaders: [String: String],
        tinfoilEvents: Set<TinfoilEvent>
    ) throws -> OpenAI {
        let urlComponents = try URLHelpers.parseHTTPURL(baseURL)
        let defaultPort = urlComponents.scheme == "https" ? 443 : 80
        var basePath = urlComponents.url.path
        while basePath.hasSuffix("/") {
            basePath.removeLast()
        }

        var mergedHeaders = customHeaders
        if let eventsHeader = tinfoilEventsHeaderValue(tinfoilEvents),
           !mergedHeaders.keys.contains(where: { $0.caseInsensitiveCompare(tinfoilEventsHeader) == .orderedSame }) {
            mergedHeaders[tinfoilEventsHeader] = eventsHeader
        }

        let configuration = OpenAI.Configuration(
            token: apiKey,
            tokenProvider: apiKeyProvider,
            host: urlComponents.host,
            port: urlComponents.port ?? defaultPort,
            scheme: urlComponents.scheme,
            basePath: basePath.isEmpty ? "/v1" : basePath,
            customHeaders: mergedHeaders,
            parsingOptions: parsingOptions
        )

        return OpenAI(
            configuration: configuration,
            customSession: session,
            streamingURLSessionFactory: streamingFactory
        )
    }
}
