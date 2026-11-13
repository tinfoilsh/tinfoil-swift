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
    let timeoutInterval: TimeInterval
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
    try refuseUnsealedTraffic(request)
    guard let url = request.url else {
        throw EHBPError(.invalidInput, "request has no URL")
    }

    let snapshot = try await verifiedState.current()
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
        // The request's idle timeout overrides the session's. URLRequest has
        // no unset timeout: it is 60 seconds unless set, as is the OpenAI
        // client's default, and every session the SDK creates also uses 60,
        // so a request that sets none keeps the timeout it had.
        timeoutInterval: request.timeoutInterval,
        body: body
    )
}

/// Refuses a request whose traffic would continue outside the bodies EHBP
/// seals: a protocol upgrade, such as a WebSocket, or a CONNECT tunnel. Sending
/// one would look protected while nothing after the handshake is. Other
/// requests are allowed, with or without a body.
func refuseUnsealedTraffic(_ request: URLRequest) throws {
    let upgrade = request.value(forHTTPHeaderField: "Upgrade") ?? ""
    guard request.httpMethod?.uppercased() != "CONNECT", upgrade.isEmpty else {
        throw TinfoilError.configuration(
            "EHBP seals only request and response bodies, so it can't protect a protocol upgrade, such as a WebSocket, or a CONNECT tunnel"
        )
    }
}

/// Follows a redirect only within one origin: a redirect elsewhere would
/// carry the request's unsealed headers and sealed body to a server the
/// client isn't bound to.
/// URLSession then returns the redirect response itself, which
/// `refusedRedirect` turns into an error.
final class EHBPRedirectPolicy: NSObject, URLSessionTaskDelegate, Sendable {
    let origin: String

    init(origin: String) {
        self.origin = origin
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        let sameOrigin = request.url.map { URLHelpers.origin(from: $0.absoluteString) == origin } ?? false
        completionHandler(sameOrigin ? request : nil)
    }
}

extension URLSession {
    /// A session for EHBP requests to `baseURL`, which follows redirects
    /// only within its origin. A session keeps its delegate until it is
    /// invalidated, so sessions are shared per origin for the life of the
    /// process rather than created per client: a process talks to few
    /// origins, while it may create many clients.
    static func ehbp(baseURL: String) -> URLSession {
        EHBPSessions.shared.session(for: URLHelpers.origin(from: baseURL))
    }
}

/// The redirect-restricted EHBP sessions, one per origin
private final class EHBPSessions: @unchecked Sendable {
    static let shared = EHBPSessions()

    private let lock = NSLock()
    private var sessions: [String: URLSession] = [:]

    func session(for origin: String) -> URLSession {
        lock.lock()
        defer { lock.unlock() }
        if let session = sessions[origin] {
            return session
        }
        let session = URLSession(configuration: .default, delegate: EHBPRedirectPolicy(origin: origin), delegateQueue: nil)
        sessions[origin] = session
        return session
    }
}

/// The error for a redirect response the session didn't follow. A redirect
/// within the origin is followed, so one that reaches the caller led
/// elsewhere.
func refusedRedirect(_ response: HTTPURLResponse, origin baseURL: String) -> TinfoilError? {
    guard (300..<400).contains(response.statusCode),
          let location = response.value(forHTTPHeaderField: "Location") else {
        return nil
    }
    return .configuration(
        "refusing redirect to \(location): EHBP requests stay on \(URLHelpers.origin(from: baseURL))"
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
    if let enclaveURL {
        _ = try URLHelpers.parseHTTPURL(enclaveURL)
    }
    _ = try EHBPClient(baseURL: baseURL, publicKey: publicKey, session: session)
    return EHBPVerifiedState(
        endpoint: EHBPVerifiedEndpoint(
            enclaveURL: enclaveURL ?? baseURL,
            publicKey: publicKey
        )
    )
}

/// How every EHBP request is sent: sealed to the current key, replayed once
/// under a refreshed key if the enclave rejects it, and refused if it was
/// redirected off its origin.
private enum EHBPReplayPolicy {
    static let maximumAttempts = 2

    /// Every attempt either returns, refreshes and continues, or throws from
    /// `refresh`, so this is unreachable in practice. It exists so a future
    /// edit to the loop cannot silently leave a request unfinished.
    static var attemptsExhausted: Error {
        EHBPError.network("EHBP retry limit exhausted")
    }

    /// Sends request through sendOnce, which receives it prepared and sealed
    /// and returns its result with the response. Only a key rejection thrown
    /// by sendOnce is replayed, so it must return once the response headers
    /// have been checked, before any of the body reaches the caller.
    static func send<Result>(
        _ request: URLRequest,
        baseURL: String,
        verifiedState: EHBPVerifiedState,
        userCacheSecret: String,
        session: URLSession,
        through sendOnce: (PreparedEHBPRequest) async throws -> (result: Result, response: URLResponse)
    ) async throws -> Result {
        for attempt in 0..<maximumAttempts {
            let prepared = try await prepareEHBPRequest(
                request,
                baseURL: baseURL,
                verifiedState: verifiedState,
                userCacheSecret: userCacheSecret,
                session: session
            )
            let sent: (result: Result, response: URLResponse)
            do {
                sent = try await sendOnce(prepared)
            } catch let error as EHBPError where error.code == .keyConfigMismatch {
                try await refresh(
                    verifiedState,
                    afterRejectedGeneration: prepared.rejectedGeneration,
                    attempt: attempt
                )
                continue
            }
            if let response = sent.response as? HTTPURLResponse, let refusal = refusedRedirect(response, origin: baseURL) {
                throw refusal
            }
            return sent.result
        }
        throw attemptsExhausted
    }

    static func refresh(
        _ verifiedState: EHBPVerifiedState,
        afterRejectedGeneration generation: UInt64,
        attempt: Int
    ) async throws {
        guard attempt + 1 < maximumAttempts else {
            throw EHBPError(.keyConfigMismatch,
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
final class EHBPURLSessionFactory: URLSessionFactory, @unchecked Sendable {
    private let baseURL: String
    private let verifiedState: EHBPVerifiedState
    let userCacheSecret: String
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
    ///     authentication-delegate configuration. By default, one that follows
    ///     redirects only within `baseURL`'s origin.
    convenience init(
        baseURL: String,
        enclaveURL: String? = nil,
        publicKey: Data,
        userCacheSecret: String = "",
        session: URLSession? = nil
    ) throws {
        self.init(
            baseURL: baseURL,
            verifiedState: try makePinnedVerifiedState(
                baseURL: baseURL,
                enclaveURL: enclaveURL,
                publicKey: publicKey,
                session: session ?? .shared
            ),
            userCacheSecret: UserCacheSecret.resolve(explicit: userCacheSecret),
            session: session
        )
    }

    /// `userCacheSecret` is already resolved; an empty one injects nothing.
    internal init(
        baseURL: String,
        verifiedState: EHBPVerifiedState,
        userCacheSecret: String = "",
        session: URLSession? = nil
    ) {
        self.baseURL = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        self.verifiedState = verifiedState
        self.userCacheSecret = userCacheSecret
        self.networkSession = session ?? .ehbp(baseURL: baseURL)
    }

    func makeUrlSession(delegate: URLSessionDataDelegateProtocol) -> URLSessionProtocol {
        return EHBPStreamingSession(
            baseURL: baseURL,
            verifiedState: verifiedState,
            userCacheSecret: userCacheSecret,
            networkSession: networkSession,
            delegate: delegate
        )
    }
}

/// EHBP-enabled session for streaming requests: each request is sealed to
/// the verified key, and its response opened chunk by chunk.
internal final class EHBPStreamingSession: StreamingSession, @unchecked Sendable {
    init(
        baseURL: String,
        verifiedState: EHBPVerifiedState,
        userCacheSecret: String = "",
        networkSession: URLSession,
        delegate: URLSessionDataDelegateProtocol
    ) {
        super.init(delegate: delegate) { request in
            // EHBP detects the key-config mismatch before any byte of the
            // rejected response is returned, so nothing leaks to the delegate
            // ahead of the replay.
            try await EHBPReplayPolicy.send(
                request,
                baseURL: baseURL,
                verifiedState: verifiedState,
                userCacheSecret: userCacheSecret,
                session: networkSession
            ) { prepared in
                let (stream, response) = try await prepared.client.requestStream(
                    method: prepared.method,
                    path: prepared.path,
                    headers: prepared.headers,
                    timeoutInterval: prepared.timeoutInterval,
                    body: prepared.body
                )
                return ((stream, response as URLResponse), response)
            }
        }
    }
}

/// The streaming task's type, kept under its EHBP name
typealias EHBPStreamingDataTask = StreamingDataTask

/// URLSession wrapper that provides EHBP encryption/decryption for all requests.
/// Conforms to URLSessionProtocol so it can be injected into the OpenAI client.
/// Delegates all crypto operations to the vetted EHBPClient.
final class EHBPURLSession: URLSessionProtocol, @unchecked Sendable {
    private let baseURL: String
    private let verifiedState: EHBPVerifiedState
    let userCacheSecret: String
    private let session: URLSession

    /// Creates an EHBP URLSession with the given server public key
    ///
    /// - Parameters:
    ///   - baseURL: Base URL where requests are sent (e.g., proxy server or enclave directly)
    ///   - enclaveURL: URL of the verified enclave (added as header when different from baseURL)
    ///   - publicKey: Server's X25519 public key (32 bytes)
    ///   - userCacheSecret: Prompt-cache scoping secret injected into eligible
    ///     request bodies before encryption. Empty values use the default.
    ///   - session: Underlying URLSession to use. By default, one that follows
    ///     redirects only within `baseURL`'s origin.
    convenience init(baseURL: String, enclaveURL: String? = nil, publicKey: Data, userCacheSecret: String = "", session: URLSession? = nil) throws {
        self.init(
            baseURL: baseURL,
            verifiedState: try makePinnedVerifiedState(
                baseURL: baseURL,
                enclaveURL: enclaveURL,
                publicKey: publicKey,
                session: session ?? .shared
            ),
            userCacheSecret: UserCacheSecret.resolve(explicit: userCacheSecret),
            session: session
        )
    }

    /// `userCacheSecret` is already resolved; an empty one injects nothing.
    internal init(
        baseURL: String,
        verifiedState: EHBPVerifiedState,
        userCacheSecret: String = "",
        session: URLSession? = nil
    ) {
        self.baseURL = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        self.verifiedState = verifiedState
        self.userCacheSecret = userCacheSecret
        self.session = session ?? .ehbp(baseURL: baseURL)
    }

    // MARK: - URLSessionProtocol

    func dataTask(
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

    func dataTask(with request: URLRequest) -> URLSessionDataTaskProtocol {
        return AsyncDataTask(request: request) { [self] in
            try await self.performRequest(request)
        } completionHandler: { _, _, _ in }
    }

    @available(iOS 15.0, macOS 12.0, tvOS 15.0, watchOS 8.0, *)
    func data(
        for request: URLRequest,
        delegate: (any URLSessionTaskDelegate)?
    ) async throws -> (Data, URLResponse) {
        return try await performRequest(request)
    }

    // MARK: - InvalidatableSession

    func invalidateAndCancel() {
    }

    func finishTasksAndInvalidate() {
    }

    // MARK: - URLSessionCombine

    #if canImport(Combine)
    func dataTaskPublisher(for request: URLRequest) -> AnyPublisher<(data: Data, response: URLResponse), URLError> {
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
        try await EHBPReplayPolicy.send(
            request,
            baseURL: baseURL,
            verifiedState: verifiedState,
            userCacheSecret: userCacheSecret,
            session: session
        ) { prepared in
            let result = try await prepared.client.request(
                method: prepared.method,
                path: prepared.path,
                headers: prepared.headers,
                timeoutInterval: prepared.timeoutInterval,
                body: prepared.body
            )
            try Task.checkCancellation()
            return ((result.data, result.response), result.response)
        }
    }

    /// Sends request as `data(for:)` does, replaying it once after a key
    /// rejection, but returns once the response headers arrive, with the body
    /// still streaming and the request's own session recovery token.
    func recoverableBytes(for request: URLRequest) async throws -> RecoverableResponse {
        try await EHBPReplayPolicy.send(
            request,
            baseURL: baseURL,
            verifiedState: verifiedState,
            userCacheSecret: userCacheSecret,
            session: session
        ) { prepared in
            let (stream, response) = try await prepared.client.requestStream(
                method: prepared.method,
                path: prepared.path,
                headers: prepared.headers,
                timeoutInterval: prepared.timeoutInterval,
                body: prepared.body
            )
            try Task.checkCancellation()
            // Each request has a client of its own, so this token is this
            // request's. EHBP withdraws it for a response that isn't sealed.
            let recoverable = RecoverableResponse(
                response: response,
                recoveryToken: try? prepared.client.getSessionRecoveryToken(),
                body: stream
            )
            return (recoverable, response)
        }
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
