import Foundation
import OpenAI

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

#if canImport(Combine)
import Combine
#endif

/// A session for the OpenAI client whose tasks each open a protected
/// response with `open` and pass its body on as it arrives: to the delegate,
/// chunk by chunk, and to a completion handler in full. Each transport mode
/// supplies its own way of opening a response.
internal class StreamingSession: URLSessionProtocol, @unchecked Sendable {
    /// Sends a request, returning once the response's headers arrive, with
    /// its body still streaming
    typealias Open = @Sendable (URLRequest) async throws -> (AsyncThrowingStream<Data, Error>, URLResponse)

    private let open: Open
    private weak var delegate: URLSessionDataDelegateProtocol?
    private var activeTasks: [ObjectIdentifier: StreamingDataTask] = [:]
    private let lock = NSLock()

    init(delegate: URLSessionDataDelegateProtocol?, open: @escaping Open) {
        self.open = open
        self.delegate = delegate
    }

    func dataTask(
        with request: URLRequest,
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionDataTaskProtocol {
        return makeTask(with: request, accumulatesResponse: true, completionHandler: completionHandler)
    }

    func dataTask(with request: URLRequest) -> URLSessionDataTaskProtocol {
        // Delegate-driven streaming path (used by the OpenAI SDK): chunks are
        // forwarded as they arrive and nobody reads the completion data, so
        // the task skips buffering the full response.
        return makeTask(with: request, accumulatesResponse: false) { _, _, _ in }
    }

    private func makeTask(
        with request: URLRequest,
        accumulatesResponse: Bool,
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) -> StreamingDataTask {
        let task = StreamingDataTask(
            request: request,
            open: open,
            delegate: delegate,
            session: self,
            accumulatesResponse: accumulatesResponse,
            completionHandler: completionHandler
        )
        lock.lock()
        activeTasks[ObjectIdentifier(task)] = task
        lock.unlock()
        return task
    }

    @available(iOS 15.0, macOS 12.0, tvOS 15.0, watchOS 8.0, *)
    func data(
        for request: URLRequest,
        delegate: (any URLSessionTaskDelegate)?
    ) async throws -> (Data, URLResponse) {
        // Cancelling the caller cancels the task, as URLSession's own
        // data(for:) does, so the request doesn't run on unobserved.
        let cancellation = TaskCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let task = dataTask(with: request) { data, response, error in
                    if let error = error {
                        continuation.resume(throwing: error)
                    } else if let data = data, let response = response {
                        continuation.resume(returning: (data, response))
                    } else if cancellation.isCancelled {
                        continuation.resume(throwing: CancellationError())
                    } else {
                        continuation.resume(throwing: URLError(.badServerResponse))
                    }
                }
                cancellation.attach(task)
                task.resume()
            }
        } onCancel: {
            cancellation.cancel()
        }
    }

    func invalidateAndCancel() {
        lock.lock()
        let tasks = activeTasks.values
        activeTasks.removeAll()
        lock.unlock()
        tasks.forEach { $0.cancel() }
    }

    func finishTasksAndInvalidate() {
        lock.lock()
        activeTasks.removeAll()
        lock.unlock()
    }

    #if canImport(Combine)
    func dataTaskPublisher(for request: URLRequest) -> AnyPublisher<(data: Data, response: URLResponse), URLError> {
        return Future<(data: Data, response: URLResponse), Error> { [self] promise in
            let task = self.dataTask(with: request) { data, response, error in
                if let error = error {
                    promise(.failure(error))
                } else if let data = data, let response = response {
                    promise(.success((data, response)))
                } else {
                    promise(.failure(URLError(.badServerResponse)))
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

    func removeTask(_ task: StreamingDataTask) {
        lock.lock()
        activeTasks.removeValue(forKey: ObjectIdentifier(task))
        lock.unlock()
    }
}

/// A data task of a `StreamingSession`: it opens its response and passes the
/// body on as it arrives.
internal final class StreamingDataTask: URLSessionDataTaskProtocol, @unchecked Sendable {
    private let request: URLRequest
    private let open: StreamingSession.Open
    private weak var delegate: URLSessionDataDelegateProtocol?
    private weak var session: StreamingSession?
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
        open: @escaping StreamingSession.Open,
        delegate: URLSessionDataDelegateProtocol?,
        session: StreamingSession,
        accumulatesResponse: Bool = true,
        completionHandler: @escaping @Sendable (Data?, URLResponse?, Error?) -> Void
    ) {
        self.request = request
        self.open = open
        self.delegate = delegate
        self.session = session
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
                error: URLError(.cancelled)
            )
            return
        }

        do {
            let (stream, response) = try await open(request)

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
                try Task.checkCancellation()
                if accumulatesResponse {
                    accumulatedData.append(chunk)
                }
                delegate?.urlSession(session, dataTask: self, didReceive: chunk)
            }
            try Task.checkCancellation()

            finish(data: accumulatedData, response: response, error: nil)
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

/// Cancels a task that may not exist yet: a cancellation that arrives first
/// is applied when the task is attached.
private final class TaskCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var task: URLSessionDataTaskProtocol?
    private var cancelled = false

    var isCancelled: Bool { lock.withLock { cancelled } }

    func attach(_ task: URLSessionDataTaskProtocol) {
        let cancelNow = lock.withLock { () -> Bool in
            self.task = task
            return cancelled
        }
        if cancelNow {
            task.cancel()
        }
    }

    func cancel() {
        let task = lock.withLock { () -> URLSessionDataTaskProtocol? in
            cancelled = true
            return self.task
        }
        task?.cancel()
    }
}
