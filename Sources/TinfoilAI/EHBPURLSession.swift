import Foundation
import OpenAI
import EHBP

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

#if canImport(Combine)
import Combine
#endif

/// Factory for creating EHBP-enabled URLSession instances for streaming requests.
/// Implements URLSessionFactory to integrate with OpenAI SDK's streaming infrastructure.
public final class EHBPURLSessionFactory: URLSessionFactory, @unchecked Sendable {
    private let baseURL: String
    private let publicKey: Data

    /// Creates an EHBP URLSession factory
    ///
    /// - Parameters:
    ///   - baseURL: Base URL for the server (e.g., "https://api.example.com")
    ///   - publicKey: Server's X25519 public key (32 bytes)
    public init(baseURL: String, publicKey: Data) {
        self.baseURL = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        self.publicKey = publicKey
    }

    public func makeUrlSession(delegate: URLSessionDataDelegateProtocol) -> URLSessionProtocol {
        return EHBPStreamingSession(
            baseURL: baseURL,
            publicKey: publicKey,
            delegate: delegate
        )
    }
}

/// EHBP-enabled session for streaming requests.
/// Wraps requests with EHBP encryption and decrypts streaming responses on the fly.
internal final class EHBPStreamingSession: URLSessionProtocol, @unchecked Sendable {
    private let baseURL: String
    private let publicKey: Data
    private weak var delegate: URLSessionDataDelegateProtocol?
    private var activeTasks: [ObjectIdentifier: EHBPStreamingDataTask] = [:]
    private let lock = NSLock()

    init(baseURL: String, publicKey: Data, delegate: URLSessionDataDelegateProtocol) {
        self.baseURL = baseURL
        self.publicKey = publicKey
        self.delegate = delegate
    }

    public func dataTask(
        with request: URLRequest,
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionDataTaskProtocol {
        let task = EHBPStreamingDataTask(
            request: request,
            baseURL: baseURL,
            publicKey: publicKey,
            delegate: delegate,
            session: self,
            completionHandler: completionHandler
        )
        lock.lock()
        activeTasks[ObjectIdentifier(task)] = task
        lock.unlock()
        return task
    }

    public func dataTask(with request: URLRequest) -> URLSessionDataTaskProtocol {
        return dataTask(with: request) { _, _, _ in }
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
    private let publicKey: Data
    private weak var delegate: URLSessionDataDelegateProtocol?
    private weak var session: EHBPStreamingSession?
    private let completionHandler: @Sendable (Data?, URLResponse?, Error?) -> Void

    private var underlyingTask: Task<Void, Never>?
    private var hasStarted = false
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
        publicKey: Data,
        delegate: URLSessionDataDelegateProtocol?,
        session: EHBPStreamingSession,
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) {
        self.request = request
        self.baseURL = baseURL
        self.publicKey = publicKey
        self.delegate = delegate
        self.session = session
        self.completionHandler = completionHandler
        self._originalRequest = request
    }

    func resume() {
        lock.lock()
        guard !hasStarted else {
            lock.unlock()
            return
        }
        hasStarted = true
        lock.unlock()

        underlyingTask = Task { [weak self] in
            guard let self = self else { return }
            await self.performStreamingRequest()
        }
    }

    func cancel() {
        lock.lock()
        let task = underlyingTask
        lock.unlock()
        task?.cancel()
        session?.removeTask(self)
    }

    private func performStreamingRequest() async {
        guard let session = session else { return }

        do {
            let ehbpClient = try EHBPClient(baseURL: baseURL, publicKey: publicKey)

            guard let url = request.url else {
                throw EHBPError.invalidInput("request has no URL")
            }

            let path = extractPath(from: url)
            let method = request.httpMethod ?? "GET"
            var headers: [String: String] = [:]
            if let allHeaders = request.allHTTPHeaderFields {
                headers = allHeaders
            }

            let (stream, response) = try await ehbpClient.requestStream(
                method: method,
                path: path,
                headers: headers,
                body: request.httpBody
            )

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
            for try await chunk in stream {
                if Task.isCancelled { break }
                accumulatedData.append(chunk)
                delegate?.urlSession(session, dataTask: self, didReceive: chunk)
            }

            completionHandler(accumulatedData, response, nil)
            delegate?.urlSession(session, task: self, didCompleteWithError: nil)
        } catch {
            completionHandler(nil, nil, error)
            delegate?.urlSession(session, task: self, didCompleteWithError: error)
        }

        session.removeTask(self)
    }

    private func extractPath(from url: URL) -> String {
        var path = url.path
        if let query = url.query {
            path += "?\(query)"
        }
        return path
    }
}

/// URLSession wrapper that provides EHBP encryption/decryption for all requests.
/// Conforms to URLSessionProtocol so it can be injected into the OpenAI client.
/// Delegates all crypto operations to the vetted EHBPClient.
public final class EHBPURLSession: URLSessionProtocol, @unchecked Sendable {
    private let ehbpClient: EHBPClient
    private let baseURL: String

    /// Creates an EHBP URLSession with the given server public key
    ///
    /// - Parameters:
    ///   - baseURL: Base URL for the server (e.g., "https://api.example.com")
    ///   - publicKey: Server's X25519 public key (32 bytes)
    ///   - session: Underlying URLSession to use (defaults to shared)
    public init(baseURL: String, publicKey: Data, session: URLSession = .shared) throws {
        self.ehbpClient = try EHBPClient(baseURL: baseURL, publicKey: publicKey, session: session)
        self.baseURL = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
    }

    // MARK: - URLSessionProtocol

    public func dataTask(
        with request: URLRequest,
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionDataTaskProtocol {
        let task = AsyncDataTask { [self] in
            try await self.performRequest(request)
        } completionHandler: { data, response, error in
            completionHandler(data, response, error)
        }
        return task
    }

    public func dataTask(with request: URLRequest) -> URLSessionDataTaskProtocol {
        return AsyncDataTask { [self] in
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
        guard let url = request.url else {
            throw EHBPError.invalidInput("request has no URL")
        }

        let path = extractPath(from: url)
        let method = request.httpMethod ?? "GET"
        var headers: [String: String] = [:]
        if let allHeaders = request.allHTTPHeaderFields {
            headers = allHeaders
        }

        let (data, response) = try await ehbpClient.request(
            method: method,
            path: path,
            headers: headers,
            body: request.httpBody
        )

        return (data, response)
    }

    private func extractPath(from url: URL) -> String {
        var path = url.path
        if let query = url.query {
            path += "?\(query)"
        }
        return path
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
        operation: @escaping @Sendable () async throws -> (Data, URLResponse),
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) {
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
