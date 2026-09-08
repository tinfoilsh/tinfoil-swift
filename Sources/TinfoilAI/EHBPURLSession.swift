import Foundation
import OpenAI
import EHBP

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

#if canImport(Combine)
import Combine
#endif

private struct PreparedEHBPRequest {
    let rejectedGeneration: UInt64
    let client: EHBPClient
    let method: String
    let path: String
    let headers: [String: String]
    let body: Data?
}

private func prepareEHBPRequest(
    _ request: URLRequest,
    baseURL: String,
    verifiedState: EHBPVerifiedState,
    userCacheSecret: String,
    session: URLSession
) async throws -> PreparedEHBPRequest {
    try Task.checkCancellation()
    guard let url = request.url else {
        throw EHBPError.invalidInput("request has no URL")
    }

    let snapshot = await verifiedState.snapshot()
    try Task.checkCancellation()
    let client = try EHBPClient(
        baseURL: baseURL,
        publicKey: snapshot.endpoint.publicKey,
        session: session
    )
    var headers = request.allHTTPHeaderFields ?? [:]
    URLHelpers.addProxyHeaderIfNeeded(
        to: &headers,
        baseURL: baseURL,
        enclaveURL: snapshot.endpoint.enclaveURL
    )
    let body = UserCacheSecret.provision(
        request: request,
        headers: &headers,
        clientSecret: userCacheSecret
    )

    return PreparedEHBPRequest(
        rejectedGeneration: snapshot.generation,
        client: client,
        method: request.httpMethod ?? "GET",
        path: URLHelpers.extractPath(from: url),
        headers: headers,
        body: body
    )
}

/// Pins a static endpoint/key pair as the initial verified state. Building a
/// throwaway client runs the same URL and X25519 key checks that requests rely
/// on later, so a misconfiguration fails at construction rather than on first use.
private func makePinnedVerifiedState(
    baseURL: String,
    enclaveURL: String?,
    publicKey: Data,
    session: URLSession
) throws -> EHBPVerifiedState {
    _ = try URLHelpers.parseHTTPURL(baseURL)
    _ = try EHBPClient(baseURL: baseURL, publicKey: publicKey, session: session)
    return EHBPVerifiedState(
        endpoint: EHBPVerifiedEndpoint(
            enclaveURL: enclaveURL ?? baseURL,
            publicKey: publicKey
        )
    )
}

private enum EHBPReplayPolicy {
    static let maximumAttempts = 2

    /// Every replay loop either returns, refreshes and continues, or throws
    /// from `refresh`, so this is unreachable in practice. It exists so a
    /// future edit to the loop cannot silently leave a request unfinished.
    static var attemptsExhausted: Error {
        EHBPError.invalidResponse("EHBP retry limit exhausted")
    }

    static func refresh(
        _ verifiedState: EHBPVerifiedState,
        afterRejectedGeneration generation: UInt64,
        attempt: Int
    ) async throws {
        guard attempt + 1 < maximumAttempts else {
            throw EHBPError.invalidResponse(
                "EHBP key configuration still mismatched after refresh"
            )
        }
        try Task.checkCancellation()
        _ = try await verifiedState.refresh(afterRejectedGeneration: generation)
        try Task.checkCancellation()
    }
}

/// Factory for creating EHBP-enabled URLSession instances for streaming requests.
/// Implements URLSessionFactory to integrate with OpenAI SDK's streaming infrastructure.
public final class EHBPURLSessionFactory: URLSessionFactory, @unchecked Sendable {
    private let baseURL: String
    private let verifiedState: EHBPVerifiedState
    private let userCacheSecret: String
    private let networkSession: URLSession

    /// Creates an EHBP URLSession factory
    ///
    /// - Parameters:
    ///   - baseURL: Base URL where requests are sent (e.g., proxy server or enclave directly)
    ///   - enclaveURL: URL of the verified enclave (added as header when different from baseURL)
    ///   - publicKey: Server's X25519 public key (32 bytes)
    ///   - userCacheSecret: Prompt-cache scoping secret injected into eligible
    ///     request bodies before encryption. Empty values use the default.
    ///   - session: Underlying network session, including any proxy or
    ///     authentication-delegate configuration.
    public convenience init(
        baseURL: String,
        enclaveURL: String? = nil,
        publicKey: Data,
        userCacheSecret: String = "",
        session: URLSession = .shared
    ) throws {
        self.init(
            baseURL: baseURL,
            verifiedState: try makePinnedVerifiedState(
                baseURL: baseURL,
                enclaveURL: enclaveURL,
                publicKey: publicKey,
                session: session
            ),
            userCacheSecret: userCacheSecret,
            session: session
        )
    }

    internal init(
        baseURL: String,
        verifiedState: EHBPVerifiedState,
        userCacheSecret: String = "",
        session: URLSession = .shared
    ) {
        self.baseURL = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        self.verifiedState = verifiedState
        self.userCacheSecret = UserCacheSecret.resolve(explicit: userCacheSecret)
        self.networkSession = session
    }

    public func makeUrlSession(delegate: URLSessionDataDelegateProtocol) -> URLSessionProtocol {
        return EHBPStreamingSession(
            baseURL: baseURL,
            verifiedState: verifiedState,
            userCacheSecret: userCacheSecret,
            networkSession: networkSession,
            delegate: delegate
        )
    }
}

/// EHBP-enabled session for streaming requests.
/// Wraps requests with EHBP encryption and decrypts streaming responses on the fly.
internal final class EHBPStreamingSession: URLSessionProtocol, @unchecked Sendable {
    private let baseURL: String
    private let verifiedState: EHBPVerifiedState
    private let userCacheSecret: String
    private let networkSession: URLSession
    private weak var delegate: URLSessionDataDelegateProtocol?
    private var activeTasks: [ObjectIdentifier: EHBPStreamingDataTask] = [:]
    private let lock = NSLock()

    init(
        baseURL: String,
        verifiedState: EHBPVerifiedState,
        userCacheSecret: String = "",
        networkSession: URLSession = .shared,
        delegate: URLSessionDataDelegateProtocol
    ) {
        self.baseURL = baseURL
        self.verifiedState = verifiedState
        self.userCacheSecret = userCacheSecret
        self.networkSession = networkSession
        self.delegate = delegate
    }

    public func dataTask(
        with request: URLRequest,
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionDataTaskProtocol {
        return makeTask(with: request, accumulatesResponse: true, completionHandler: completionHandler)
    }

    public func dataTask(with request: URLRequest) -> URLSessionDataTaskProtocol {
        // Delegate-driven streaming path (used by the OpenAI SDK): chunks are
        // forwarded as they arrive and nobody reads the completion data, so
        // the task skips buffering the full response.
        return makeTask(with: request, accumulatesResponse: false) { _, _, _ in }
    }

    private func makeTask(
        with request: URLRequest,
        accumulatesResponse: Bool,
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) -> EHBPStreamingDataTask {
        let task = EHBPStreamingDataTask(
            request: request,
            baseURL: baseURL,
            verifiedState: verifiedState,
            userCacheSecret: userCacheSecret,
            delegate: delegate,
            session: self,
            networkSession: networkSession,
            accumulatesResponse: accumulatesResponse,
            completionHandler: completionHandler
        )
        lock.lock()
        activeTasks[ObjectIdentifier(task)] = task
        lock.unlock()
        return task
    }

    @available(iOS 15.0, macOS 12.0, tvOS 15.0, watchOS 8.0, *)
    public func data(
        for request: URLRequest,
        delegate: (any URLSessionTaskDelegate)?
    ) async throws -> (Data, URLResponse) {
        return try await withCheckedThrowingContinuation { continuation in
            let task = dataTask(with: request) { data, response, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let data = data, let response = response {
                    continuation.resume(returning: (data, response))
                } else {
                    continuation.resume(throwing: EHBPError.invalidResponse("Missing data or response"))
                }
            }
            task.resume()
        }
    }

    public func invalidateAndCancel() {
        lock.lock()
        let tasks = activeTasks.values
        activeTasks.removeAll()
        lock.unlock()
        tasks.forEach { $0.cancel() }
    }

    public func finishTasksAndInvalidate() {
        lock.lock()
        activeTasks.removeAll()
        lock.unlock()
    }

    #if canImport(Combine)
    public func dataTaskPublisher(for request: URLRequest) -> AnyPublisher<(data: Data, response: URLResponse), URLError> {
        return Future<(data: Data, response: URLResponse), Error> { [self] promise in
            let task = self.dataTask(with: request) { data, response, error in
                if let error = error {
                    promise(.failure(error))
                } else if let data = data, let response = response {
                    promise(.success((data, response)))
                } else {
                    promise(.failure(EHBPError.invalidResponse("Missing data or response")))
                }
            }
            task.resume()
        }
        .mapError { error -> URLError in
            if let urlError = error as? URLError {
                return urlError
            }
            return URLError(.cannotDecodeContentData)
        }
        .eraseToAnyPublisher()
    }
    #endif

    func removeTask(_ task: EHBPStreamingDataTask) {
        lock.lock()
        activeTasks.removeValue(forKey: ObjectIdentifier(task))
        lock.unlock()
    }
}

/// Data task that performs EHBP-encrypted streaming requests.
/// Encrypts the request body and decrypts streaming response chunks.
internal final class EHBPStreamingDataTask: URLSessionDataTaskProtocol, @unchecked Sendable {
    private let request: URLRequest
    private let baseURL: String
    private let verifiedState: EHBPVerifiedState
    private let userCacheSecret: String
    private let networkSession: URLSession
    private weak var delegate: URLSessionDataDelegateProtocol?
    private weak var session: EHBPStreamingSession?
    /// Whether the full decrypted response is buffered for the completion
    /// handler. The delegate-driven streaming path disables this because its
    /// completion handler discards the data, so buffering would only double
    /// peak memory for large responses.
    let accumulatesResponse: Bool
    private let completionHandler: @Sendable (Data?, URLResponse?, Error?) -> Void

    private var underlyingTask: Task<Void, Never>?
    private var hasStarted = false
    private var isCancellationRequested = false
    private var hasCompleted = false
    private let lock = NSLock()
    private var _originalRequest: URLRequest?

    var originalRequest: URLRequest? {
        lock.lock()
        defer { lock.unlock() }
        return _originalRequest
    }

    init(
        request: URLRequest,
        baseURL: String,
        verifiedState: EHBPVerifiedState,
        userCacheSecret: String = "",
        delegate: URLSessionDataDelegateProtocol?,
        session: EHBPStreamingSession,
        networkSession: URLSession,
        accumulatesResponse: Bool = true,
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) {
        self.request = request
        self.baseURL = baseURL
        self.verifiedState = verifiedState
        self.userCacheSecret = userCacheSecret
        self.delegate = delegate
        self.session = session
        self.networkSession = networkSession
        self.accumulatesResponse = accumulatesResponse
        self.completionHandler = completionHandler
        self._originalRequest = request
    }

    func resume() {
        lock.lock()
        guard !hasStarted, !isCancellationRequested else {
            lock.unlock()
            return
        }
        hasStarted = true
        let task = Task { [self] in
            await performStreamingRequest()
        }
        underlyingTask = task
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        guard !isCancellationRequested, !hasCompleted else {
            lock.unlock()
            return
        }
        isCancellationRequested = true
        let task = underlyingTask
        let shouldCompleteImmediately = !hasStarted
        lock.unlock()
        task?.cancel()
        if shouldCompleteImmediately {
            Task { [self] in
                finish(data: nil, response: nil, error: nil)
            }
        }
    }

    private func performStreamingRequest() async {
        guard let session = session else {
            finish(
                data: nil,
                response: nil,
                error: EHBPError.invalidInput("session was deallocated")
            )
            return
        }

        do {
            for attempt in 0..<EHBPReplayPolicy.maximumAttempts {
                let prepared = try await prepareEHBPRequest(
                    request,
                    baseURL: baseURL,
                    verifiedState: verifiedState,
                    userCacheSecret: userCacheSecret,
                    session: networkSession
                )

                let (stream, response) = try await prepared.client.requestStream(
                    method: prepared.method,
                    path: prepared.path,
                    headers: prepared.headers,
                    body: prepared.body
                )
                var iterator = stream.makeAsyncIterator()
                var prefetchedChunks: [Data] = []
                var problemBody = Data()
                var reachedEnd = false

                if EHBPProblemResponse.shouldInspectKeyConfigurationMismatch(response) {
                    var diagnosticWasTruncated = false
                    while let chunk = try await iterator.next() {
                        prefetchedChunks.append(chunk)
                        if EHBPProblemResponse.appendDiagnosticPrefix(
                            chunk,
                            to: &problemBody
                        ) {
                            diagnosticWasTruncated = true
                            break
                        }
                    }
                    reachedEnd = !diagnosticWasTruncated
                    if reachedEnd,
                       EHBPProblemResponse.isKeyConfigurationMismatch(
                           response: response,
                           body: problemBody
                       ) {
                        try await EHBPReplayPolicy.refresh(
                            verifiedState,
                            afterRejectedGeneration: prepared.rejectedGeneration,
                            attempt: attempt
                        )
                        continue
                    }
                }

                delegate?.urlSession(
                    session,
                    dataTask: self,
                    didReceive: response
                ) { disposition in
                    if disposition == .cancel {
                        self.cancel()
                    }
                }

                var accumulatedData = Data()
                for chunk in prefetchedChunks {
                    try Task.checkCancellation()
                    if accumulatesResponse {
                        accumulatedData.append(chunk)
                    }
                    delegate?.urlSession(session, dataTask: self, didReceive: chunk)
                }
                if !reachedEnd {
                    while let chunk = try await iterator.next() {
                        try Task.checkCancellation()
                        if accumulatesResponse {
                            accumulatedData.append(chunk)
                        }
                        delegate?.urlSession(session, dataTask: self, didReceive: chunk)
                    }
                }
                try Task.checkCancellation()

                finish(data: accumulatedData, response: response, error: nil)
                return
            }
            throw EHBPReplayPolicy.attemptsExhausted
        } catch {
            finish(data: nil, response: nil, error: error)
        }
    }

    private func finish(data: Data?, response: URLResponse?, error: Error?) {
        lock.lock()
        guard !hasCompleted else {
            lock.unlock()
            return
        }
        hasCompleted = true
        underlyingTask = nil
        let wasCancelled = isCancellationRequested
        let finalData = wasCancelled ? nil : data
        let finalResponse = wasCancelled ? nil : response
        let finalError: Error? = wasCancelled ? URLError(.cancelled) : error
        lock.unlock()

        completionHandler(finalData, finalResponse, finalError)
        if let session {
            delegate?.urlSession(session, task: self, didCompleteWithError: finalError)
            session.removeTask(self)
        }
    }
}

/// URLSession wrapper that provides EHBP encryption/decryption for all requests.
/// Conforms to URLSessionProtocol so it can be injected into the OpenAI client.
/// Delegates all crypto operations to the vetted EHBPClient.
public final class EHBPURLSession: URLSessionProtocol, @unchecked Sendable {
    private let baseURL: String
    private let verifiedState: EHBPVerifiedState
    private let userCacheSecret: String
    private let session: URLSession

    /// Creates an EHBP URLSession with the given server public key
    ///
    /// - Parameters:
    ///   - baseURL: Base URL where requests are sent (e.g., proxy server or enclave directly)
    ///   - enclaveURL: URL of the verified enclave (added as header when different from baseURL)
    ///   - publicKey: Server's X25519 public key (32 bytes)
    ///   - userCacheSecret: Prompt-cache scoping secret injected into eligible
    ///     request bodies before encryption. Empty values use the default.
    ///   - session: Underlying URLSession to use (defaults to shared)
    public convenience init(baseURL: String, enclaveURL: String? = nil, publicKey: Data, userCacheSecret: String = "", session: URLSession = .shared) throws {
        self.init(
            baseURL: baseURL,
            verifiedState: try makePinnedVerifiedState(
                baseURL: baseURL,
                enclaveURL: enclaveURL,
                publicKey: publicKey,
                session: session
            ),
            userCacheSecret: userCacheSecret,
            session: session
        )
    }

    internal init(
        baseURL: String,
        verifiedState: EHBPVerifiedState,
        userCacheSecret: String = "",
        session: URLSession = .shared
    ) {
        self.baseURL = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        self.verifiedState = verifiedState
        self.userCacheSecret = UserCacheSecret.resolve(explicit: userCacheSecret)
        self.session = session
    }

    // MARK: - URLSessionProtocol

    public func dataTask(
        with request: URLRequest,
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionDataTaskProtocol {
        let task = AsyncDataTask(request: request) { [self] in
            try await self.performRequest(request)
        } completionHandler: { data, response, error in
            completionHandler(data, response, error)
        }
        return task
    }

    public func dataTask(with request: URLRequest) -> URLSessionDataTaskProtocol {
        return AsyncDataTask(request: request) { [self] in
            try await self.performRequest(request)
        } completionHandler: { _, _, _ in }
    }

    @available(iOS 15.0, macOS 12.0, tvOS 15.0, watchOS 8.0, *)
    public func data(
        for request: URLRequest,
        delegate: (any URLSessionTaskDelegate)?
    ) async throws -> (Data, URLResponse) {
        return try await performRequest(request)
    }

    // MARK: - InvalidatableSession

    public func invalidateAndCancel() {
    }

    public func finishTasksAndInvalidate() {
    }

    // MARK: - URLSessionCombine

    #if canImport(Combine)
    public func dataTaskPublisher(for request: URLRequest) -> AnyPublisher<(data: Data, response: URLResponse), URLError> {
        return Future<(data: Data, response: URLResponse), Error> { [self] promise in
            Task {
                do {
                    let result = try await self.performRequest(request)
                    promise(.success(result))
                } catch {
                    promise(.failure(error))
                }
            }
        }
        .mapError { error -> URLError in
            if let urlError = error as? URLError {
                return urlError
            }
            return URLError(.cannotDecodeContentData)
        }
        .eraseToAnyPublisher()
    }
    #endif

    // MARK: - Private

    private func performRequest(_ request: URLRequest) async throws -> (Data, URLResponse) {
        for attempt in 0..<EHBPReplayPolicy.maximumAttempts {
            let prepared = try await prepareEHBPRequest(
                request,
                baseURL: baseURL,
                verifiedState: verifiedState,
                userCacheSecret: userCacheSecret,
                session: session
            )
            let (data, response) = try await prepared.client.request(
                method: prepared.method,
                path: prepared.path,
                headers: prepared.headers,
                body: prepared.body
            )
            try Task.checkCancellation()

            if EHBPProblemResponse.isKeyConfigurationMismatch(
                response: response,
                body: data
            ) {
                try await EHBPReplayPolicy.refresh(
                    verifiedState,
                    afterRejectedGeneration: prepared.rejectedGeneration,
                    attempt: attempt
                )
                continue
            }

            return (data, response)
        }
        throw EHBPReplayPolicy.attemptsExhausted
    }
}

// MARK: - Helper Classes

/// Async data task that wraps an async operation
private final class AsyncDataTask: URLSessionDataTaskProtocol, @unchecked Sendable {
    private let operation: @Sendable () async throws -> (Data, URLResponse)
    private let completionHandler: @Sendable (Data?, URLResponse?, Error?) -> Void
    private var task: Task<Void, Never>?
    private var hasStarted = false
    private let lock = NSLock()
    private var _originalRequest: URLRequest?

    var originalRequest: URLRequest? { _originalRequest }

    init(
        request: URLRequest,
        operation: @escaping @Sendable () async throws -> (Data, URLResponse),
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) {
        self._originalRequest = request
        self.operation = operation
        self.completionHandler = completionHandler
    }

    func resume() {
        lock.lock()
        guard !hasStarted else {
            lock.unlock()
            return
        }
        hasStarted = true
        task = Task {
            do {
                let (data, response) = try await operation()
                completionHandler(data, response, nil)
            } catch {
                completionHandler(nil, nil, error)
            }
        }
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        let currentTask = task
        lock.unlock()
        currentTask?.cancel()
    }
}
