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

    private static func makeVerifier(
        githubRepo: String,
        enclaveURL: String?,
        pinnedMeasurement: AttestationMeasurement? = nil,
        vmShape: VMShape? = nil
    ) throws -> SecureClient {
        // A pin without an enclave must never degrade to release-based
        // verification, so the invariant is enforced here rather than relying
        // on every caller's guard.
        if let pinnedMeasurement {
            guard let enclaveURL else {
                throw TinfoilError.invalidConfiguration("pinnedMeasurement requires enclaveURL")
            }
            return SecureClient(
                enclaveURL: enclaveURL,
                pinnedMeasurement: pinnedMeasurement,
                vmShape: vmShape
            )
        }
        return SecureClient(
            githubRepo: githubRepo,
            enclaveURL: enclaveURL
        )
    }

    /// Selects the enclave a key-rotation refresh re-verifies. Re-verification
    /// must target the same enclave the caller chose (an explicit `enclaveURL`
    /// or a pinned measurement is a destination constraint). The one exception
    /// is a client that discovered its enclave through an EHBP forwarding proxy:
    /// ATC may rotate the endpoint/key pair behind the proxy, so only then does
    /// refresh rediscover by returning nil.
    internal static func refreshEnclaveURL(
        verifiedEnclaveURL: String,
        configuredEnclaveURL: String?,
        baseURL: String?,
        pinned: Bool
    ) -> String? {
        if baseURL == nil || configuredEnclaveURL != nil || pinned {
            return verifiedEnclaveURL
        }
        return nil
    }

    /// Creates a new TinfoilAI client configured for communication with a Tinfoil enclave
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from TINFOIL_API_KEY environment variable
    ///   - baseURL: Optional URL where requests are sent (e.g., a proxy server). If not provided, requests go directly to the enclave.
    ///   - enclaveURL: Optional enclave to verify and connect to. If not provided, the enclave
    ///     is selected by the Go verifier's router discovery. Explicit URLs must use HTTPS;
    ///     schemeless hosts default to HTTPS. Required with `pinnedMeasurement`.
    ///   - githubRepo: Expected code-provenance repository. Custom repositories require `enclaveURL`.
    ///   - pinnedMeasurement: Verify the enclave against this measurement instead of the
    ///     signed code provenance in the v3 document. The pin's provenance must be established
    ///     out of band; platform endorsements, freshness, and quote verification still run.
    ///     Requires `enclaveURL`; cannot be combined with a custom `githubRepo`.
    ///   - vmShape: With `pinnedMeasurement`, the VM shape the pinned code was built for.
    ///     Required for TDX enclaves (the endorsed platform measurement is resolved under
    ///     it); ignored for SEV-SNP. Rejected without `pinnedMeasurement`.
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
    ///   - onVerification: Optional callback for verification results. Invoked
    ///     once during `create`, and again from the request's task context
    ///     whenever the enclave rotates its key and the client re-attests
    ///     before replaying the request.
    /// - Returns: A TinfoilAI client configured for secure communication (use like OpenAI client)
    ///
    /// When using a proxy, set `baseURL` to your proxy server. Attestation is fetched directly
    /// from the configured or discovered enclave using a fresh nonce. The SDK encrypts requests
    /// with EHBP. The proxy receives the `X-Tinfoil-Enclave-Url`
    /// header to know where to forward requests.
    public static func create(
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        baseURL: String? = nil,
        enclaveURL: String? = nil,
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        pinnedMeasurement: AttestationMeasurement? = nil,
        vmShape: VMShape? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        tinfoilEvents: Set<TinfoilEvent> = [],
        userCacheSecret: String? = nil,
        onVerification: VerificationCallback? = nil
    ) async throws -> TinfoilAI {
        let staticApiKey = apiKey ?? ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        // Attestation itself does not use the API key; it only authorizes
        // inference requests. Require that a bearer can be resolved either
        // statically or via the dynamic provider, so a caller using a rotating
        // token (e.g. a short-lived JWT) is not forced to pass a placeholder key.
        guard staticApiKey != nil || apiKeyProvider != nil else {
            throw TinfoilError.missingAPIKey
        }

        if pinnedMeasurement != nil {
            guard enclaveURL != nil else {
                throw TinfoilError.invalidConfiguration(
                    "pinnedMeasurement requires enclaveURL: a pinned measurement cannot be verified against an auto-selected router"
                )
            }
            guard githubRepo == TinfoilConstants.defaultGithubRepo else {
                throw TinfoilError.invalidConfiguration("pinnedMeasurement cannot be combined with githubRepo")
            }
        } else if vmShape != nil {
            throw TinfoilError.invalidConfiguration("vmShape requires pinnedMeasurement")
        }

        let configuredEnclaveURL = enclaveURL
        let verifier = try makeVerifier(
            githubRepo: githubRepo,
            enclaveURL: configuredEnclaveURL,
            pinnedMeasurement: pinnedMeasurement,
            vmShape: vmShape
        )

        do {
            let groundTruth = try await verifier.verify()

            guard let enclaveURL = verifier.verifiedEnclaveURL else {
                throw TinfoilError.invalidConfiguration("Verification succeeded but enclave URL not available")
            }

            onVerification?(verifier.verificationDocument)

            let finalBaseURL = baseURL ?? enclaveURL
            let pinnedRefreshEnclaveURL = refreshEnclaveURL(
                verifiedEnclaveURL: enclaveURL,
                configuredEnclaveURL: configuredEnclaveURL,
                baseURL: baseURL,
                pinned: pinnedMeasurement != nil
            )
            let refreshEndpoint: EHBPVerifiedState.Refresh = {
                let refreshVerifier = try Self.makeVerifier(
                    githubRepo: githubRepo,
                    enclaveURL: pinnedRefreshEnclaveURL,
                    pinnedMeasurement: pinnedMeasurement,
                    vmShape: vmShape
                )

                defer { onVerification?(refreshVerifier.verificationDocument) }
                let refreshedTruth = try await refreshVerifier.verify()
                guard let refreshedURL = refreshVerifier.verifiedEnclaveURL,
                      let keyHex = refreshedTruth.hpkePublicKey,
                      let key = Data(hexString: keyHex),
                      key.count == TinfoilConstants.hpkePublicKeyByteCount
                else {
                    throw TinfoilError.invalidConfiguration(
                        "Refreshed attestation did not provide a valid enclave HPKE key"
                    )
                }
                return EHBPVerifiedEndpoint(enclaveURL: refreshedURL, publicKey: key)
            }

            return try TinfoilAI(
                apiKey: staticApiKey,
                apiKeyProvider: apiKeyProvider,
                baseURL: finalBaseURL,
                enclaveURL: enclaveURL,
                hpkePublicKeyHex: groundTruth.hpkePublicKey,
                parsingOptions: parsingOptions,
                customHeaders: customHeaders,
                tinfoilEvents: tinfoilEvents,
                userCacheSecret: UserCacheSecret.resolve(explicit: userCacheSecret),
                refreshEndpoint: refreshEndpoint
            )
        } catch {
            onVerification?(verifier.verificationDocument)
            throw error
        }
    }

    /// Internal initializer that sets up the EHBP session and OpenAI client.
    /// `userCacheSecret` is the already-resolved prompt-cache scoping secret
    /// (see `UserCacheSecret.resolve`).
    internal convenience init(
        apiKey: String?,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        baseURL: String,
        enclaveURL: String,
        hpkePublicKeyHex: String?,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        tinfoilEvents: Set<TinfoilEvent> = [],
        userCacheSecret: String = "",
        refreshEndpoint: EHBPVerifiedState.Refresh? = nil
    ) throws {
        guard let hpkeKeyHex = hpkePublicKeyHex, !hpkeKeyHex.isEmpty else {
            throw TinfoilError.invalidConfiguration("Server does not support EHBP (no HPKE public key)")
        }

        guard let hpkePublicKey = Data(hexString: hpkeKeyHex),
              hpkePublicKey.count == TinfoilConstants.hpkePublicKeyByteCount else {
            throw TinfoilError.invalidConfiguration("Invalid HPKE public key format (expected 32 bytes)")
        }

        let urlComponents = try URLHelpers.parseHTTPURL(baseURL)

        let verifiedState = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(
                enclaveURL: enclaveURL,
                publicKey: hpkePublicKey
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
}
