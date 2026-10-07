import Foundation
@_exported import OpenAI
import EHBP

/// Main entry point for the Tinfoil client library.
/// Provides the same API as OpenAI client with EHBP encryption for secure enclave communication.
public class TinfoilAI {
    private let openAIClient: OpenAI

    private init(client: OpenAI) {
        self.openAIClient = client
    }

    /// Creates a new TinfoilAI client configured for communication with a Tinfoil enclave
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from TINFOIL_API_KEY environment variable
    ///   - baseURL: Optional URL where requests are sent (e.g., a proxy server). If not provided, requests go directly to the enclave.
    ///   - handle: Verifies the enclave this client sends to. When nil, a
    ///     default handle discovers and verifies one of Tinfoil's routers.
    ///     Configure an `EnclaveHandle` to choose the enclave, pin the repo,
    ///     relay attestation, tighten the policy, or observe and reject
    ///     verifications. The client verifies through it on create and on
    ///     every refresh.
    ///   - parsingOptions: Parsing options for handling different providers.
    ///   - customHeaders: Additional request headers to forward verbatim on
    ///     every outbound request (merged over the headers synthesized by
    ///     `tinfoilEvents`; caller values win on conflict). Use for arbitrary
    ///     router / proxy pass-through headers.
    ///   - tinfoilEvents: Optional set of Tinfoil-specific progress events
    ///     to opt into. Each selected event contributes one comma-separated
    ///     value on the `X-Tinfoil-Events` request header so the router
    ///     emits `<tinfoil-event>...</tinfoil-event>` markers inline with
    ///     the assistant text. Strict OpenAI SDKs render the markers as
    ///     text; callers parse and strip them before display.
    ///   - userCacheSecret: Scopes the router's prompt cache. `nil` (the
    ///     default) resolves the secret from `TINFOIL_USER_CACHE_SECRET` or a
    ///     generated value persisted at `~/.tinfoil/user_cache_secret`; a
    ///     non-empty string pins it (use one stable value per end user). An
    ///     empty string is treated as unset.
    ///     Servers holding many end users' conversations should instead set
    ///     the `user_cache_secret` field per request (e.g. via
    ///     `ChatQuery.extraBody`). A non-empty per-request string wins over the
    ///     client-level secret; an empty string is replaced with it.
    /// - Returns: A TinfoilAI client configured for secure communication (use like OpenAI client)
    ///
    /// When using a proxy, set `baseURL` to it. Request bodies stay encrypted
    /// to the verified enclave, and the proxy receives the
    /// `X-Tinfoil-Enclave-Url` header to know where to forward requests. To
    /// fetch attestation through the proxy as well, give the handle an
    /// `attestationRelay`.
    public static func create(
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        baseURL: String? = nil,
        handle: EnclaveHandle? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        tinfoilEvents: Set<TinfoilEvent> = [],
        userCacheSecret: String? = nil
    ) async throws -> TinfoilAI {
        let staticApiKey = apiKey ?? ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        // Attestation itself does not use the API key; it only authorizes
        // inference requests. Require that a bearer can be resolved either
        // statically or via the dynamic provider, so a caller using a rotating
        // token (e.g. a short-lived JWT) is not forced to pass a placeholder key.
        guard staticApiKey != nil || apiKeyProvider != nil else {
            throw TinfoilError.missingAPIKey
        }

        let handle = try handle ?? EnclaveHandle()
        let verification = try await handle.verify()
        let enclaveURL = Self.enclaveURL(for: verification)
        return try TinfoilAI(
            apiKey: staticApiKey,
            apiKeyProvider: apiKeyProvider,
            baseURL: baseURL ?? enclaveURL,
            enclaveURL: enclaveURL,
            hpkePublicKeyHex: verification.hpkePublicKey,
            expiresAt: verification.freshnessExpiresAt,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            tinfoilEvents: tinfoilEvents,
            userCacheSecret: UserCacheSecret.resolve(explicit: userCacheSecret),
            refreshEndpoint: {
                // The client stays with the enclave it verified; a refresh
                // re-verifies that enclave for a current key and deadline.
                let refreshed = try await handle.verify()
                return EHBPVerifiedEndpoint(
                    enclaveURL: Self.enclaveURL(for: refreshed),
                    publicKey: try Self.ehbpPublicKey(hex: refreshed.hpkePublicKey),
                    expiresAt: refreshed.freshnessExpiresAt
                )
            }
        )
    }

    private static func enclaveURL(for verification: Verification) -> String {
        "https://\(verification.enclaveHost)"
    }

    /// The X25519 key EHBP encrypts request bodies to, from its hex form
    private static func ehbpPublicKey(hex: String?) throws -> Data {
        guard let hex, !hex.isEmpty else {
            throw TinfoilError.invalidConfiguration("Server does not support EHBP (no HPKE public key)")
        }
        guard let key = Data(hexString: hex), key.count == TinfoilConstants.hpkePublicKeyByteCount else {
            throw TinfoilError.invalidConfiguration("Invalid HPKE public key format (expected 32 bytes)")
        }
        return key
    }

    /// Internal initializer that sets up the EHBP session and OpenAI client.
    /// `userCacheSecret` is the already-resolved prompt-cache scoping secret
    /// (see `UserCacheSecret.resolve`). `expiresAt` is when the key's
    /// attestation stops authorizing new requests.
    internal convenience init(
        apiKey: String?,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        baseURL: String,
        enclaveURL: String,
        hpkePublicKeyHex: String?,
        expiresAt: Date = .distantFuture,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        tinfoilEvents: Set<TinfoilEvent> = [],
        userCacheSecret: String = "",
        refreshEndpoint: EHBPVerifiedState.Refresh? = nil
    ) throws {
        let hpkePublicKey = try Self.ehbpPublicKey(hex: hpkePublicKeyHex)

        let urlComponents = try URLHelpers.parseHTTPURL(baseURL)

        let verifiedState = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(
                enclaveURL: enclaveURL,
                publicKey: hpkePublicKey,
                expiresAt: expiresAt
            ),
            refresh: refreshEndpoint
        )

        let ehbpSession = EHBPURLSession(
            baseURL: baseURL,
            verifiedState: verifiedState,
            userCacheSecret: userCacheSecret
        )

        let ehbpStreamingFactory = EHBPURLSessionFactory(
            baseURL: baseURL,
            verifiedState: verifiedState,
            userCacheSecret: userCacheSecret
        )

        let defaultPort = urlComponents.scheme == "https" ? 443 : 80

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
            customHeaders: mergedHeaders,
            parsingOptions: parsingOptions
        )

        let openAIClient = OpenAI(
            configuration: configuration,
            customSession: ehbpSession,
            streamingURLSessionFactory: ehbpStreamingFactory
        )

        self.init(client: openAIClient)
    }

    // MARK: - OpenAI API Forwarding (Async)

    public func chats(query: ChatQuery) async throws -> ChatResult {
        try await openAIClient.chats(query: query)
    }

    /// Sends a chat completion with additional headers applied to this call
    /// only, on top of the client's `customHeaders`. Use this for values that
    /// change per request, such as a conversation id.
    public func chats(query: ChatQuery, headers: [String: String]) async throws -> ChatResult {
        try await openAIClient.chats(query: query, headers: headers)
    }

    public func chatsStream(query: ChatQuery) -> AsyncThrowingStream<ChatStreamResult, Error> {
        openAIClient.chatsStream(query: query)
    }

    /// Streams a chat completion with additional headers applied to this call
    /// only, on top of the client's `customHeaders`. Use this for values that
    /// change per request, such as a conversation id.
    public func chatsStream(query: ChatQuery, headers: [String: String]) -> AsyncThrowingStream<ChatStreamResult, Error> {
        openAIClient.chatsStream(query: query, headers: headers)
    }

    public func images(query: ImagesQuery) async throws -> ImagesResult {
        try await openAIClient.images(query: query)
    }

    public func imageEdits(query: ImageEditsQuery) async throws -> ImagesResult {
        try await openAIClient.imageEdits(query: query)
    }

    public func imageVariations(query: ImageVariationsQuery) async throws -> ImagesResult {
        try await openAIClient.imageVariations(query: query)
    }

    public func embeddings(query: EmbeddingsQuery) async throws -> EmbeddingsResult {
        try await openAIClient.embeddings(query: query)
    }

    public func model(query: ModelQuery) async throws -> ModelResult {
        try await openAIClient.model(query: query)
    }

    public func models() async throws -> ModelsResult {
        try await openAIClient.models()
    }

    public func moderations(query: ModerationsQuery) async throws -> ModerationsResult {
        try await openAIClient.moderations(query: query)
    }

    public func audioCreateSpeech(query: AudioSpeechQuery) async throws -> AudioSpeechResult {
        try await openAIClient.audioCreateSpeech(query: query)
    }

    public func audioCreateSpeechStream(query: AudioSpeechQuery) -> AsyncThrowingStream<AudioSpeechResult, Error> {
        openAIClient.audioCreateSpeechStream(query: query)
    }

    /// Streams EHBP-encrypted speech with response validation options, such as
    /// requiring `audio/pcm` before delivering bytes to a PCM player.
    public func audioCreateSpeechStream(query: AudioSpeechQuery, options: AudioSpeechStreamOptions) -> AsyncThrowingStream<AudioSpeechResult, Error> {
        openAIClient.audioCreateSpeechStream(query: query, options: options)
    }

    public func audioTranscriptions(query: AudioTranscriptionQuery) async throws -> AudioTranscriptionResult {
        try await openAIClient.audioTranscriptions(query: query)
    }

    public func audioTranscriptionsVerbose(query: AudioTranscriptionQuery) async throws -> AudioTranscriptionVerboseResult {
        try await openAIClient.audioTranscriptionsVerbose(query: query)
    }

    public func audioTranscriptionStream(query: AudioTranscriptionQuery) -> AsyncThrowingStream<AudioTranscriptionStreamResult, Error> {
        openAIClient.audioTranscriptionStream(query: query)
    }

    public func audioTranslations(query: AudioTranslationQuery) async throws -> AudioTranslationResult {
        try await openAIClient.audioTranslations(query: query)
    }

    public func assistants() async throws -> AssistantsResult {
        try await openAIClient.assistants()
    }

    public func assistants(after: String?) async throws -> AssistantsResult {
        try await openAIClient.assistants(after: after)
    }

    public func assistantCreate(query: AssistantsQuery) async throws -> AssistantResult {
        try await openAIClient.assistantCreate(query: query)
    }

    public func assistantModify(query: AssistantsQuery, assistantId: String) async throws -> AssistantResult {
        try await openAIClient.assistantModify(query: query, assistantId: assistantId)
    }

    public func threads(query: ThreadsQuery) async throws -> ThreadsResult {
        try await openAIClient.threads(query: query)
    }

    public func threadRun(query: ThreadRunQuery) async throws -> RunResult {
        try await openAIClient.threadRun(query: query)
    }

    public func runs(threadId: String, query: RunsQuery) async throws -> RunResult {
        try await openAIClient.runs(threadId: threadId, query: query)
    }

    public func runRetrieve(threadId: String, runId: String) async throws -> RunResult {
        try await openAIClient.runRetrieve(threadId: threadId, runId: runId)
    }

    public func runRetrieveSteps(threadId: String, runId: String) async throws -> RunRetrieveStepsResult {
        try await openAIClient.runRetrieveSteps(threadId: threadId, runId: runId)
    }

    public func runRetrieveSteps(threadId: String, runId: String, before: String?) async throws -> RunRetrieveStepsResult {
        try await openAIClient.runRetrieveSteps(threadId: threadId, runId: runId, before: before)
    }

    public func runSubmitToolOutputs(threadId: String, runId: String, query: RunToolOutputsQuery) async throws -> RunResult {
        try await openAIClient.runSubmitToolOutputs(threadId: threadId, runId: runId, query: query)
    }

    public func threadsMessages(threadId: String) async throws -> ThreadsMessagesResult {
        try await openAIClient.threadsMessages(threadId: threadId)
    }

    public func threadsMessages(threadId: String, before: String?) async throws -> ThreadsMessagesResult {
        try await openAIClient.threadsMessages(threadId: threadId, before: before)
    }

    public func threadsAddMessage(threadId: String, query: MessageQuery) async throws -> ThreadAddMessageResult {
        try await openAIClient.threadsAddMessage(threadId: threadId, query: query)
    }

    public func files(query: FilesQuery) async throws -> FilesResult {
        try await openAIClient.files(query: query)
    }

    // MARK: - Responses API

    public func createResponse(query: CreateModelResponseQuery) async throws -> ResponseObject {
        try await openAIClient.responses.createResponse(query: query)
    }

    public func createResponseStream(query: CreateModelResponseQuery) -> AsyncThrowingStream<ResponseStreamEvent, Error> {
        openAIClient.responses.createResponseStreaming(query: query)
    }
}

/// Errors that can occur when using the Tinfoil client
public enum TinfoilError: Error, Equatable {
    case missingAPIKey
    case invalidConfiguration(String)
    case connectionError(String)
    /// The enclave's attestation document could not be fetched
    case fetchError(String)
    /// The enclave's attestation was rejected or could not be used
    case attestationError(String)
    /// An `onEnclaveVerified` callback rejected the enclave
    case enclaveRejected(String)
}

/// Gives `localizedDescription` each error's message, rather than Foundation's
/// generic "The operation couldn't be completed" with an enum case number.
extension TinfoilError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .missingAPIKey:
            return "no API key was given; pass apiKey or apiKeyProvider, or set TINFOIL_API_KEY"
        case .invalidConfiguration(let message), .connectionError(let message), .fetchError(let message),
             .attestationError(let message), .enclaveRejected(let message):
            return message
        }
    }
}
