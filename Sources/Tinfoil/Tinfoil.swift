import Foundation
@_exported import OpenAI
import EHBP

/// Main entry point for the Tinfoil client library.
/// Provides the same API as OpenAI client with EHBP encryption for secure enclave communication.
public class TinfoilAI {
    /// This SDK's version, as tinfoil-go's `Version()` reports its own
    public static let version = TinfoilConstants.sdkVersion

    private let openAIClient: OpenAI

    private init(client: OpenAI) {
        self.openAIClient = client
    }

    /// Creates a TinfoilAI client that sends OpenAI requests through an
    /// `EnclaveHTTPClient`, so every request body is sealed to the verified
    /// enclave with EHBP, as tinfoil-go's `NewClient` and
    /// `NewEnclaveOpenAIClient` do. It verifies the enclave before returning,
    /// so a client that cannot be used fails here.
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from TINFOIL_API_KEY environment variable
    ///   - client: The enclave client requests go through, which must use
    ///     `TransportMode.ehbp`. When nil, `EnclaveHTTPClient.discoverRouter()`
    ///     picks one of Tinfoil's routers. Create one to choose the enclave,
    ///     pin the repo, send through a proxy with `baseURL`, relay
    ///     attestation, tighten the policy, scope the prompt cache, or
    ///     observe and reject verifications.
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
    /// - Returns: A TinfoilAI client configured for secure communication (use like OpenAI client)
    ///
    /// Servers holding many end users' conversations should set the
    /// `user_cache_secret` field per request (e.g. via `ChatQuery.extraBody`);
    /// a non-empty per-request string wins over the client's secret.
    public static func create(
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        client: EnclaveHTTPClient? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        tinfoilEvents: Set<TinfoilEvent> = []
    ) async throws -> TinfoilAI {
        let staticApiKey = apiKey ?? ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        // Attestation itself does not use the API key; it only authorizes
        // inference requests. Require that a bearer can be resolved either
        // statically or via the dynamic provider, so a caller using a rotating
        // token (e.g. a short-lived JWT) is not forced to pass a placeholder key.
        guard staticApiKey != nil || apiKeyProvider != nil else {
            throw TinfoilError.configuration("no API key was given; pass apiKey or apiKeyProvider, or set TINFOIL_API_KEY")
        }

        let client = if let client { client } else { try await EnclaveHTTPClient.discoverRouter() }
        guard let ehbp = client.ehbp else {
            throw TinfoilError.configuration(
                "TinfoilAI seals requests with EHBP, so its EnclaveHTTPClient must use TransportMode.ehbp"
            )
        }
        // Fail here rather than on the first request, including for an
        // enclave that endorses no HPKE key.
        let verified = try await client.ensureVerified()
        _ = try EHBPVerifiedEndpoint(verification: verified)
        return try TinfoilAI(
            apiKey: staticApiKey,
            apiKeyProvider: apiKeyProvider,
            baseURL: client.baseURL.absoluteString,
            session: ehbp.session,
            streamingFactory: ehbp.streamingFactory,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            tinfoilEvents: tinfoilEvents
        )
    }

    /// Internal initializer that seals to a fixed enclave key, for tests.
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
        let verifiedState = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(
                enclaveURL: enclaveURL,
                publicKey: try EHBPVerifiedEndpoint.publicKey(hex: hpkePublicKeyHex),
                expiresAt: expiresAt
            ),
            refresh: refreshEndpoint
        )
        try self.init(
            apiKey: apiKey,
            apiKeyProvider: apiKeyProvider,
            baseURL: baseURL,
            session: EHBPURLSession(baseURL: baseURL, verifiedState: verifiedState, userCacheSecret: userCacheSecret),
            streamingFactory: EHBPURLSessionFactory(baseURL: baseURL, verifiedState: verifiedState, userCacheSecret: userCacheSecret),
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            tinfoilEvents: tinfoilEvents
        )
    }

    /// Sets up the OpenAI client over the given EHBP sessions. Requests go to
    /// `baseURL`, under its path if it has one, as tinfoil-go's OpenAI clients
    /// use a base URL as is, and under `/v1` for a bare origin.
    private convenience init(
        apiKey: String?,
        apiKeyProvider: (@Sendable () -> String?)?,
        baseURL: String,
        session: EHBPURLSession,
        streamingFactory: EHBPURLSessionFactory,
        parsingOptions: ParsingOptions,
        customHeaders: [String: String],
        tinfoilEvents: Set<TinfoilEvent>
    ) throws {
        let urlComponents = try URLHelpers.parseHTTPURL(baseURL)
        let defaultPort = urlComponents.scheme == "https" ? 443 : 80
        var basePath = URL(string: baseURL)?.path ?? ""
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

        let openAIClient = OpenAI(
            configuration: configuration,
            customSession: session,
            streamingURLSessionFactory: streamingFactory
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

/// Errors that can occur when using the Tinfoil client, in the three
/// categories tinfoil-go reports. Each case carries a struct of details, as
/// `DecodingError` does, so a detail can be added without breaking callers.
/// Errors from the inference API itself keep their own types.
public enum TinfoilError: Error, Equatable {
    /// The caller's arguments or client configuration are invalid, as is a
    /// request the client refuses to send, such as one leaving the verified
    /// enclave. Retrying will not help.
    case configurationError(Configuration)
    /// The client could not fetch the attestation material it needed.
    case networkError(Network)
    /// The enclave's evidence, the policy or the channel binding was rejected,
    /// including by an `onEnclaveVerified` callback.
    case attestationError(Attestation)

    /// Details of a configuration error
    public struct Configuration: Equatable, Sendable {
        public let message: String
    }

    /// Details of a network error
    public struct Network: Equatable, Sendable {
        public let message: String
        /// Set when the request failed in transit, as when offline or timed
        /// out. Neither this nor `status` is set when the SDK refused the
        /// response itself, as for one too large or a redirect off HTTPS.
        public let urlError: URLError?
        /// Set when the server answered with an HTTP error status
        public let status: Int?
    }

    /// Details of an attestation error
    public struct Attestation: Equatable, Sendable {
        public let message: String
        /// The layer of the verifier that rejected the attestation document,
        /// when it did
        public let layer: VerificationLayer?
    }

    /// The error's message, whatever its category
    public var message: String {
        switch self {
        case .configurationError(let details):
            return details.message
        case .networkError(let details):
            return details.message
        case .attestationError(let details):
            return details.message
        }
    }
}

/// Shorthand the SDK throws with, each building its case's details: for
/// example, `.attestation("rejected")` is
/// `.attestationError(Attestation(message: "rejected", layer: nil))`.
extension TinfoilError {
    static func configuration(_ message: String) -> TinfoilError {
        .configurationError(Configuration(message: message))
    }

    static func network(_ message: String, urlError: URLError? = nil, status: Int? = nil) -> TinfoilError {
        .networkError(Network(message: message, urlError: urlError, status: status))
    }

    static func attestation(_ message: String, layer: VerificationLayer? = nil) -> TinfoilError {
        .attestationError(Attestation(message: message, layer: layer))
    }
}

/// The verification layer that rejected an attestation document, as
/// tinfoil-go's `verify.Layer` names it. More layers may be added, so match
/// the ones you handle and tolerate any other.
public struct VerificationLayer: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    /// A document that can't be parsed or isn't bound to the request
    public static let envelope = VerificationLayer(rawValue: "envelope")
    /// Reference values that fail to authenticate
    public static let provenance = VerificationLayer(rawValue: "provenance")
    /// Hardware evidence that isn't authentic
    public static let quote = VerificationLayer(rawValue: "quote")
    /// Authentic evidence that doesn't satisfy the policy
    public static let policy = VerificationLayer(rawValue: "policy")

    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public var description: String { rawValue }
}

/// Gives `localizedDescription` each error's message, rather than Foundation's
/// generic "The operation couldn't be completed" with an enum case number.
extension TinfoilError: LocalizedError {
    public var errorDescription: String? {
        message
    }
}
