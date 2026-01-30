import Foundation
import OpenAI
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
    ///   - githubRepo: GitHub repository containing the enclave config
    ///   - attestationBundleURL: Optional URL to fetch a precomputed attestation bundle from.
    ///     If not provided, uses the default ATC endpoint. The enclave URL is discovered from
    ///     the attestation bundle during verification.
    ///   - parsingOptions: Parsing options for handling different providers.
    ///   - onVerification: Optional callback for verification results
    /// - Returns: A TinfoilAI client configured for secure communication (use like OpenAI client)
    ///
    /// When using a proxy, set both `baseURL` and `attestationBundleURL` to your proxy server
    /// (e.g., "http://localhost:8080"). The SDK will fetch the attestation bundle through the proxy,
    /// verify the enclave, and encrypt requests with EHBP. The proxy receives the `X-Tinfoil-Enclave-Url`
    /// header to know where to forward requests.
    public static func create(
        apiKey: String? = nil,
        baseURL: String? = nil,
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        attestationBundleURL: String? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        onVerification: VerificationCallback? = nil
    ) async throws -> TinfoilAI {
        let finalApiKey = apiKey ?? ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        guard let finalApiKey = finalApiKey else {
            throw TinfoilError.missingAPIKey
        }

        let verifier = SecureClient(
            githubRepo: githubRepo,
            attestationBundleURL: attestationBundleURL
        )

        do {
            let groundTruth = try await verifier.verify()

            guard let enclaveURL = verifier.verifiedEnclaveURL else {
                throw TinfoilError.invalidConfiguration("Verification succeeded but enclave URL not available")
            }

            onVerification?(verifier.verificationDocument)

            let finalBaseURL = baseURL ?? enclaveURL

            return try TinfoilAI(
                apiKey: finalApiKey,
                baseURL: finalBaseURL,
                enclaveURL: enclaveURL,
                hpkePublicKeyHex: groundTruth.hpkePublicKey,
                parsingOptions: parsingOptions
            )
        } catch {
            onVerification?(verifier.verificationDocument)
            throw error
        }
    }

    /// Internal initializer that sets up the EHBP session and OpenAI client
    internal convenience init(
        apiKey: String,
        baseURL: String,
        enclaveURL: String,
        hpkePublicKeyHex: String?,
        parsingOptions: ParsingOptions = .relaxed
    ) throws {
        guard let hpkeKeyHex = hpkePublicKeyHex, !hpkeKeyHex.isEmpty else {
            throw TinfoilError.invalidConfiguration("Server does not support EHBP (no HPKE public key)")
        }

        guard let hpkePublicKey = Data(hexString: hpkeKeyHex), hpkePublicKey.count == 32 else {
            throw TinfoilError.invalidConfiguration("Invalid HPKE public key format (expected 32 bytes)")
        }

        let ehbpSession = try EHBPURLSession(
            baseURL: baseURL,
            enclaveURL: enclaveURL,
            publicKey: hpkePublicKey
        )

        let ehbpStreamingFactory = EHBPURLSessionFactory(
            baseURL: baseURL,
            enclaveURL: enclaveURL,
            publicKey: hpkePublicKey
        )

        let urlComponents = try URLHelpers.parseURL(baseURL)
        let defaultPort = urlComponents.scheme == "https" ? 443 : 80

        let configuration = OpenAI.Configuration(
            token: apiKey,
            host: urlComponents.host,
            port: urlComponents.port ?? defaultPort,
            scheme: urlComponents.scheme,
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

    public func chatsStream(query: ChatQuery) -> AsyncThrowingStream<ChatStreamResult, Error> {
        openAIClient.chatsStream(query: query)
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
