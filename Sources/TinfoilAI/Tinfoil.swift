import Foundation
import OpenAI
import EHBP

/// Main entry point for the Tinfoil client library.
/// Provides the same API as OpenAI client with EHBP encryption for secure enclave communication.
public class TinfoilAI {
    private let ehbpClient: EHBPClient
    private let baseURL: String
    private let apiKey: String

    private init(ehbpClient: EHBPClient, baseURL: String, apiKey: String) {
        self.ehbpClient = ehbpClient
        self.baseURL = baseURL
        self.apiKey = apiKey
    }

    /// Creates a new TinfoilAI client configured for communication with a Tinfoil enclave
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from TINFOIL_API_KEY environment variable
    ///   - enclaveURL: Optional URL of the Tinfoil enclave. If not provided, will fetch from router API
    ///   - githubRepo: GitHub repository containing the enclave config
    ///   - onVerification: Optional callback for verification results
    /// - Returns: A TinfoilAI client configured for secure communication
    public static func create(
        apiKey: String? = nil,
        enclaveURL: String? = nil,
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        onVerification: VerificationCallback? = nil
    ) async throws -> TinfoilAI {
        let finalApiKey = apiKey ?? ProcessInfo.processInfo.environment["TINFOIL_API_KEY"]
        guard let finalApiKey = finalApiKey else {
            throw TinfoilError.missingAPIKey
        }

        let finalEnclaveURL: String
        if let providedURL = enclaveURL {
            finalEnclaveURL = providedURL
        } else {
            let routerAddress = try await RouterManager.fetchRouter()
            finalEnclaveURL = "https://\(routerAddress)"
        }

        let verifier = SecureClient(
            githubRepo: githubRepo,
            enclaveURL: finalEnclaveURL
        )

        do {
            let groundTruth = try await verifier.verify()
            let verificationDocument = verifier.getVerificationDocument()
            onVerification?(verificationDocument)

            guard let hpkeKeyHex = groundTruth.hpkePublicKey, !hpkeKeyHex.isEmpty else {
                throw TinfoilError.invalidConfiguration("Server does not support EHBP (no HPKE public key)")
            }

            guard let hpkePublicKey = Data(hexString: hpkeKeyHex) else {
                throw TinfoilError.invalidConfiguration("Invalid HPKE public key format")
            }

            let client = try EHBPClient(baseURL: finalEnclaveURL, publicKey: hpkePublicKey)

            return TinfoilAI(
                ehbpClient: client,
                baseURL: finalEnclaveURL,
                apiKey: finalApiKey
            )
        } catch {
            let verificationDocument = verifier.getVerificationDocument()
            onVerification?(verificationDocument)
            throw error
        }
    }

    // MARK: - Chat Completions

    public func chats(query: ChatQuery) async throws -> ChatResult {
        let body = try JSONEncoder().encode(query)
        let (data, response) = try await ehbpClient.request(
            method: "POST",
            path: "/v1/chat/completions",
            headers: defaultHeaders(),
            body: body
        )

        guard response.statusCode == 200 else {
            let errorMessage = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw TinfoilError.connectionError("HTTP \(response.statusCode): \(errorMessage)")
        }

        return try JSONDecoder().decode(ChatResult.self, from: data)
    }

    public func chatsStream(query: ChatQuery) -> AsyncThrowingStream<ChatStreamResult, Error> {
        AsyncThrowingStream { continuation in
            Task {
                do {
                    var streamQuery = query
                    streamQuery.stream = true

                    let body = try JSONEncoder().encode(streamQuery)
                    let (stream, response) = try await ehbpClient.requestStream(
                        method: "POST",
                        path: "/v1/chat/completions",
                        headers: defaultHeaders(),
                        body: body
                    )

                    guard response.statusCode == 200 else {
                        var errorData = Data()
                        for try await chunk in stream {
                            errorData.append(chunk)
                        }
                        let errorMessage = String(data: errorData, encoding: .utf8) ?? "Unknown error"
                        throw TinfoilError.connectionError("HTTP \(response.statusCode): \(errorMessage)")
                    }

                    var buffer = Data()
                    for try await chunk in stream {
                        buffer.append(chunk)

                        while let lineRange = buffer.range(of: Data("\n".utf8)) {
                            let lineData = buffer.subdata(in: buffer.startIndex..<lineRange.lowerBound)
                            buffer.removeSubrange(buffer.startIndex...lineRange.lowerBound)

                            guard let line = String(data: lineData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                                  !line.isEmpty else {
                                continue
                            }

                            if line.hasPrefix("data: ") {
                                let jsonString = String(line.dropFirst(6))
                                if jsonString == "[DONE]" {
                                    continuation.finish()
                                    return
                                }

                                if let jsonData = jsonString.data(using: .utf8) {
                                    let result = try JSONDecoder().decode(ChatStreamResult.self, from: jsonData)
                                    continuation.yield(result)
                                }
                            }
                        }
                    }

                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
        }
    }

    // MARK: - Embeddings

    public func embeddings(query: EmbeddingsQuery) async throws -> EmbeddingsResult {
        let body = try JSONEncoder().encode(query)
        let (data, response) = try await ehbpClient.request(
            method: "POST",
            path: "/v1/embeddings",
            headers: defaultHeaders(),
            body: body
        )

        guard response.statusCode == 200 else {
            let errorMessage = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw TinfoilError.connectionError("HTTP \(response.statusCode): \(errorMessage)")
        }

        return try JSONDecoder().decode(EmbeddingsResult.self, from: data)
    }

    // MARK: - Models

    public func models() async throws -> ModelsResult {
        let (data, response) = try await ehbpClient.request(
            method: "GET",
            path: "/v1/models",
            headers: ["Authorization": "Bearer \(apiKey)"],
            body: nil
        )

        guard response.statusCode == 200 else {
            let errorMessage = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw TinfoilError.connectionError("HTTP \(response.statusCode): \(errorMessage)")
        }

        return try JSONDecoder().decode(ModelsResult.self, from: data)
    }

    public func model(query: ModelQuery) async throws -> ModelResult {
        let (data, response) = try await ehbpClient.request(
            method: "GET",
            path: "/v1/models/\(query.model)",
            headers: ["Authorization": "Bearer \(apiKey)"],
            body: nil
        )

        guard response.statusCode == 200 else {
            let errorMessage = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw TinfoilError.connectionError("HTTP \(response.statusCode): \(errorMessage)")
        }

        return try JSONDecoder().decode(ModelResult.self, from: data)
    }

    // MARK: - Responses API

    public func createResponse(query: CreateModelResponseQuery) async throws -> ResponseObject {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/responses", body: body)
    }

    public func createResponseStream(query: CreateModelResponseQuery) -> AsyncThrowingStream<ResponseStreamEvent, Error> {
        AsyncThrowingStream { continuation in
            Task {
                do {
                    let streamQuery = CreateModelResponseQuery(
                        input: query.input,
                        model: query.model,
                        include: query.include,
                        background: query.background,
                        instructions: query.instructions,
                        maxOutputTokens: query.maxOutputTokens,
                        metadata: query.metadata,
                        parallelToolCalls: query.parallelToolCalls,
                        previousResponseId: query.previousResponseId,
                        prompt: query.prompt,
                        reasoning: query.reasoning,
                        serviceTier: query.serviceTier,
                        store: query.store,
                        stream: true,
                        temperature: query.temperature,
                        text: query.text,
                        toolChoice: query.toolChoice,
                        tools: query.tools,
                        topP: query.topP,
                        truncation: query.truncation,
                        user: query.user
                    )

                    let body = try JSONEncoder().encode(streamQuery)
                    let (stream, response) = try await ehbpClient.requestStream(
                        method: "POST",
                        path: "/v1/responses",
                        headers: defaultHeaders(),
                        body: body
                    )

                    guard response.statusCode == 200 else {
                        var errorData = Data()
                        for try await chunk in stream {
                            errorData.append(chunk)
                        }
                        let errorMessage = String(data: errorData, encoding: .utf8) ?? "Unknown error"
                        throw TinfoilError.connectionError("HTTP \(response.statusCode): \(errorMessage)")
                    }

                    var buffer = Data()
                    for try await chunk in stream {
                        buffer.append(chunk)

                        while let lineRange = buffer.range(of: Data("\n".utf8)) {
                            let lineData = buffer.subdata(in: buffer.startIndex..<lineRange.lowerBound)
                            buffer.removeSubrange(buffer.startIndex...lineRange.lowerBound)

                            guard let line = String(data: lineData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                                  !line.isEmpty else {
                                continue
                            }

                            if line.hasPrefix("data: ") {
                                let jsonString = String(line.dropFirst(6))
                                if jsonString == "[DONE]" {
                                    continuation.finish()
                                    return
                                }

                                if let jsonData = jsonString.data(using: .utf8) {
                                    let result = try JSONDecoder().decode(ResponseStreamEvent.self, from: jsonData)
                                    continuation.yield(result)
                                }
                            }
                        }
                    }

                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
        }
    }

    public func getResponse(id: String) async throws -> ResponseObject {
        return try await performRequest(method: "GET", path: "/v1/responses/\(id)", body: nil)
    }

    public func deleteResponse(id: String) async throws -> DeleteModelResponseResult {
        return try await performRequest(method: "DELETE", path: "/v1/responses/\(id)", body: nil)
    }

    // MARK: - Assistants

    public func assistants(after: String? = nil) async throws -> AssistantsResult {
        let path = buildPath("/v1/assistants", queryItems: ["after": after])
        return try await performRequest(method: "GET", path: path, body: nil)
    }

    public func assistantCreate(query: AssistantsQuery) async throws -> AssistantResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/assistants", body: body)
    }

    public func assistantModify(assistantId: String, query: AssistantsQuery) async throws -> AssistantResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/assistants/\(assistantId)", body: body)
    }

    // MARK: - Threads

    public func threads(query: ThreadsQuery) async throws -> ThreadsResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/threads", body: body)
    }

    public func threadsAddMessage(threadId: String, query: MessageQuery) async throws -> ThreadAddMessageResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/threads/\(threadId)/messages", body: body)
    }

    public func threadsMessages(threadId: String, before: String? = nil) async throws -> ThreadsMessagesResult {
        let path = buildPath("/v1/threads/\(threadId)/messages", queryItems: ["before": before])
        return try await performRequest(method: "GET", path: path, body: nil)
    }

    // MARK: - Runs

    public func runs(threadId: String, query: RunsQuery) async throws -> RunResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/threads/\(threadId)/runs", body: body)
    }

    public func runRetrieve(threadId: String, runId: String) async throws -> RunResult {
        return try await performRequest(method: "GET", path: "/v1/threads/\(threadId)/runs/\(runId)", body: nil)
    }

    public func runRetrieveSteps(threadId: String, runId: String, before: String? = nil) async throws -> RunRetrieveStepsResult {
        let path = buildPath("/v1/threads/\(threadId)/runs/\(runId)/steps", queryItems: ["before": before])
        return try await performRequest(method: "GET", path: path, body: nil)
    }

    public func runSubmitToolOutputs(threadId: String, runId: String, query: RunToolOutputsQuery) async throws -> RunResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/threads/\(threadId)/runs/\(runId)/submit_tool_outputs", body: body)
    }

    public func threadRun(query: ThreadRunQuery) async throws -> RunResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/threads/runs", body: body)
    }

    // MARK: - Files

    public func files(query: FilesQuery) async throws -> FilesResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/files", body: body)
    }

    // MARK: - Images

    public func images(query: ImagesQuery) async throws -> ImagesResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/images/generations", body: body)
    }

    public func imageEdits(query: ImageEditsQuery) async throws -> ImagesResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/images/edits", body: body)
    }

    public func imageVariations(query: ImageVariationsQuery) async throws -> ImagesResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/images/variations", body: body)
    }

    // MARK: - Audio

    public func audioTranscriptions(query: AudioTranscriptionQuery) async throws -> AudioTranscriptionResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/audio/transcriptions", body: body)
    }

    public func audioTranslations(query: AudioTranslationQuery) async throws -> AudioTranslationResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/audio/translations", body: body)
    }

    public func audioCreateSpeech(query: AudioSpeechQuery) async throws -> AudioSpeechResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/audio/speech", body: body)
    }

    // MARK: - Moderations

    public func moderations(query: ModerationsQuery) async throws -> ModerationsResult {
        let body = try JSONEncoder().encode(query)
        return try await performRequest(method: "POST", path: "/v1/moderations", body: body)
    }

    // MARK: - Helper Methods

    private func defaultHeaders() -> [String: String] {
        return [
            "Content-Type": "application/json",
            "Authorization": "Bearer \(apiKey)"
        ]
    }

    private func buildPath(_ basePath: String, queryItems: [String: String?]) -> String {
        let items = queryItems.compactMapValues { $0 }
        guard !items.isEmpty else { return basePath }

        var components = URLComponents(string: basePath)!
        components.queryItems = items.map { URLQueryItem(name: $0.key, value: $0.value) }
        return components.string!
    }

    private func performRequest<T: Decodable>(method: String, path: String, body: Data?) async throws -> T {
        let (data, response) = try await ehbpClient.request(
            method: method,
            path: path,
            headers: defaultHeaders(),
            body: body
        )

        guard response.statusCode == 200 else {
            let errorMessage = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw TinfoilError.connectionError("HTTP \(response.statusCode): \(errorMessage)")
        }

        return try JSONDecoder().decode(T.self, from: data)
    }
}

/// Errors that can occur when using the Tinfoil client
public enum TinfoilError: Error, Equatable {
    case missingAPIKey
    case invalidConfiguration(String)
    case connectionError(String)
}
