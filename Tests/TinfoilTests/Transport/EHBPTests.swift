import XCTest
import Foundation
import OpenAI
import EHBP
@testable import Tinfoil

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Captured HTTP request data from local server
struct CapturedHTTPRequest: Sendable {
    let method: String
    let path: String
    let headers: [String: String]
    let body: Data?
}

/// Thread-safe storage for captured HTTP requests
final class HTTPRequestStore: @unchecked Sendable {
    private let lock = NSLock()
    private var _requests: [CapturedHTTPRequest] = []

    var requests: [CapturedHTTPRequest] {
        lock.lock()
        defer { lock.unlock() }
        return _requests
    }

    var lastRequest: CapturedHTTPRequest? {
        requests.last
    }

    func append(_ request: CapturedHTTPRequest) {
        lock.lock()
        _requests.append(request)
        lock.unlock()
    }

    func clear() {
        lock.lock()
        _requests.removeAll()
        lock.unlock()
    }
}

/// Simple local HTTP server for testing that captures incoming requests
final class LocalTestServer: @unchecked Sendable {
    private var serverSocket: Int32 = -1
    private var isRunning = false
    private var serverTask: Task<Void, Never>?
    let requestStore = HTTPRequestStore()
    let port: UInt16

    struct Response {
        var statusCode: Int
        var contentType: String
        var body: Data
        var includeNonce: Bool
        /// Sent as the Location header, for redirects
        var location: String? = nil
    }

    var responseNonce: String = Data(repeating: 0xAB, count: 32).hexString
    var responseBody: Data = Data()
    var responseStatusCode: Int = 200
    var responseContentType: String = "application/json"
    var includeResponseNonce = true
    /// Responses served in order, one per request, before falling back to the
    /// default fields above.
    var queuedResponses: [Response] = []
    var responseHandler: ((CapturedHTTPRequest) -> Response)?

    init(port: UInt16 = 0) {
        self.port = port
    }

    var baseURL: String {
        "http://127.0.0.1:\(actualPort)"
    }

    private var actualPort: UInt16 = 0

    func start() throws {
        serverSocket = socket(AF_INET, SOCK_STREAM, 0)
        guard serverSocket >= 0 else {
            throw NSError(domain: "LocalTestServer", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to create socket"])
        }

        var reuse: Int32 = 1
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = INADDR_ANY

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                bind(serverSocket, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard bindResult >= 0 else {
            close(serverSocket)
            throw NSError(domain: "LocalTestServer", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to bind socket"])
        }

        var boundAddr = sockaddr_in()
        var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &boundAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                getsockname(serverSocket, sockaddrPtr, &addrLen)
            }
        }
        actualPort = UInt16(bigEndian: boundAddr.sin_port)

        guard listen(serverSocket, 5) >= 0 else {
            close(serverSocket)
            throw NSError(domain: "LocalTestServer", code: 3, userInfo: [NSLocalizedDescriptionKey: "Failed to listen"])
        }

        isRunning = true
        serverTask = Task { [weak self] in
            await self?.acceptConnections()
        }
    }

    func stop() {
        isRunning = false
        serverTask?.cancel()
        if serverSocket >= 0 {
            close(serverSocket)
            serverSocket = -1
        }
    }

    private func acceptConnections() async {
        while isRunning && !Task.isCancelled {
            var clientAddr = sockaddr_in()
            var clientAddrLen = socklen_t(MemoryLayout<sockaddr_in>.size)

            let clientSocket = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    accept(serverSocket, sockaddrPtr, &clientAddrLen)
                }
            }

            guard clientSocket >= 0 else {
                continue
            }

            handleClient(clientSocket)
        }
    }

    private func handleClient(_ clientSocket: Int32) {
        defer { close(clientSocket) }

        var allData = Data()
        var buffer = [UInt8](repeating: 0, count: 65536)

        while true {
            let bytesRead = recv(clientSocket, &buffer, buffer.count, 0)
            if bytesRead <= 0 { break }

            allData.append(Data(buffer[0..<bytesRead]))

            let crlfcrlf: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
            guard let headerEndRange = allData.range(of: Data(crlfcrlf)) else {
                continue
            }

            let headerData = allData.prefix(upTo: headerEndRange.lowerBound)
            guard let headerString = String(data: headerData, encoding: .utf8) else {
                break
            }

            var contentLength = 0
            for line in headerString.components(separatedBy: "\r\n") {
                if line.lowercased().hasPrefix("content-length:") {
                    let value = line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)
                    contentLength = Int(value) ?? 0
                    break
                }
            }

            let bodyStart = headerEndRange.upperBound
            let expectedTotalLength = bodyStart + contentLength
            if allData.count >= expectedTotalLength {
                break
            }
        }

        guard !allData.isEmpty else { return }

        var customResponse: Response?
        if let request = parseHTTPRequest(allData) {
            requestStore.append(request)
            customResponse = responseHandler?(request)
        }

        let response = buildHTTPResponse(customResponse)
        _ = response.withUnsafeBytes { ptr in
            send(clientSocket, ptr.baseAddress, response.count, 0)
        }
    }

    private func parseHTTPRequest(_ data: Data) -> CapturedHTTPRequest? {
        let crlfcrlf: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
        guard let headerEndIndex = data.range(of: Data(crlfcrlf)) else {
            return nil
        }

        let headerData = data.prefix(upTo: headerEndIndex.lowerBound)
        guard let headerString = String(data: headerData, encoding: .utf8) else {
            return nil
        }

        let lines = headerString.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return nil }

        let requestLine = lines[0].components(separatedBy: " ")
        guard requestLine.count >= 2 else { return nil }

        let method = requestLine[0]
        let path = requestLine[1]

        var headers: [String: String] = [:]
        for i in 1..<lines.count {
            let line = lines[i]
            if line.isEmpty { break }
            if let colonIndex = line.firstIndex(of: ":") {
                let key = String(line[..<colonIndex]).trimmingCharacters(in: .whitespaces)
                let value = String(line[line.index(after: colonIndex)...]).trimmingCharacters(in: .whitespaces)
                headers[key] = value
            }
        }

        var body: Data? = nil
        let bodyStartIndex = headerEndIndex.upperBound
        if bodyStartIndex < data.count {
            body = data.suffix(from: bodyStartIndex)
        }

        return CapturedHTTPRequest(method: method, path: path, headers: headers, body: body)
    }

    private func buildHTTPResponse(_ customResponse: Response? = nil) -> Data {
        let next = customResponse ?? (queuedResponses.isEmpty
            ? Response(
                statusCode: responseStatusCode,
                contentType: responseContentType,
                body: responseBody,
                includeNonce: includeResponseNonce
            )
            : queuedResponses.removeFirst())
        var response = "HTTP/1.1 \(next.statusCode) OK\r\n"
        response += "Content-Type: \(next.contentType)\r\n"
        if let location = next.location {
            response += "Location: \(location)\r\n"
        }
        if next.includeNonce {
            response += "\(EHBPProtocol.responseNonceHeader): \(responseNonce)\r\n"
        }
        response += "Content-Length: \(next.body.count)\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"

        var responseData = Data(response.utf8)
        responseData.append(next.body)
        return responseData
    }
}

final class EHBPTests: XCTestCase {

    // MARK: - Test Constants

    /// A valid 32-byte X25519 public key for testing
    private let testPublicKey = Data(repeating: 0x42, count: 32)

    private var server: LocalTestServer!

    override func setUp() async throws {
        try await super.setUp()
        server = LocalTestServer()
        server.responseBody = makeEncryptedResponse()
        try server.start()
    }

    override func tearDown() async throws {
        server.stop()
        server = nil
        try await super.tearDown()
    }

    private func makeStreamingSession(
        delegate: URLSessionDataDelegateProtocol,
        verifiedState: EHBPVerifiedState? = nil
    ) -> EHBPStreamingSession {
        EHBPStreamingSession(
            baseURL: server.baseURL,
            verifiedState: verifiedState ?? EHBPVerifiedState(
                endpoint: EHBPVerifiedEndpoint(
                    enclaveURL: server.baseURL,
                    publicKey: testPublicKey
                )
            ),
            networkSession: .ehbp(baseURL: server.baseURL),
            delegate: delegate
        )
    }

    // MARK: - EHBP Header Tests

    func testEHBPRequestContainsEncapsulatedKeyHeader() async throws {
        let ehbpClient = try EHBPClient(
            baseURL: server.baseURL,
            publicKey: testPublicKey
        )

        let testBody = Data("{\"test\": \"data\"}".utf8)

        do {
            _ = try await ehbpClient.request(
                method: "POST",
                path: "/v1/chat/completions",
                headers: ["Content-Type": "application/json"],
                body: testBody
            )
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Request should contain \(EHBPProtocol.encapsulatedKeyHeader) header")

        if let keyHex = encapsulatedKeyHeader {
            XCTAssertEqual(keyHex.count, 64, "Encapsulated key should be 32 bytes (64 hex chars)")
            XCTAssertTrue(keyHex.allSatisfy { $0.isHexDigit }, "Encapsulated key should be valid hex")
        }
    }

    func testEHBPRequestBodyIsEncrypted() async throws {
        let ehbpClient = try EHBPClient(
            baseURL: server.baseURL,
            publicKey: testPublicKey
        )

        let plainTextBody = """
        {
            "model": "gpt-oss-120b",
            "messages": [{"role": "user", "content": "Hello"}]
        }
        """
        let testBody = Data(plainTextBody.utf8)

        do {
            _ = try await ehbpClient.request(
                method: "POST",
                path: "/v1/chat/completions",
                headers: ["Content-Type": "application/json"],
                body: testBody
            )
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest,
              let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        XCTAssertNotEqual(capturedBody, testBody, "Request body should be encrypted, not plain text")

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("model"), "Encrypted body should not contain plaintext 'model'")
            XCTAssertFalse(bodyString.contains("messages"), "Encrypted body should not contain plaintext 'messages'")
            XCTAssertFalse(bodyString.contains("Hello"), "Encrypted body should not contain plaintext 'Hello'")
        }

        let decoder = JSONDecoder()
        let jsonParseResult = try? decoder.decode([String: String].self, from: capturedBody)
        XCTAssertNil(jsonParseResult, "Encrypted body should not be parseable as JSON")
    }

    func testEHBPPassesThroughCustomHeaders() async throws {
        let ehbpClient = try EHBPClient(
            baseURL: server.baseURL,
            publicKey: testPublicKey
        )

        let customHeaders = [
            "Content-Type": "application/json",
            "Authorization": "Bearer test-token-12345",
            "X-Custom-Header": "custom-value"
        ]

        do {
            _ = try await ehbpClient.request(
                method: "POST",
                path: "/v1/chat/completions",
                headers: customHeaders,
                body: Data("{\"test\": true}".utf8)
            )
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured")
            return
        }

        XCTAssertEqual(
            capturedRequest.headers["Content-Type"],
            "application/json",
            "Content-Type header should be passed through"
        )
        XCTAssertEqual(
            capturedRequest.headers["Authorization"],
            "Bearer test-token-12345",
            "Authorization header should be passed through"
        )
        XCTAssertEqual(
            capturedRequest.headers["X-Custom-Header"],
            "custom-value",
            "Custom headers should be passed through"
        )
    }

    func testEHBPRequestWithoutBodyHasNoEncapsulatedKey() async throws {
        server.responseBody = Data("{}".utf8)

        let ehbpClient = try EHBPClient(
            baseURL: server.baseURL,
            publicKey: testPublicKey
        )

        _ = try await ehbpClient.request(
            method: "GET",
            path: "/v1/models",
            headers: [:],
            body: nil
        )

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNil(encapsulatedKeyHeader, "GET request without body should not have encapsulated key header")
    }

    func testEHBPRequestPreservesHTTPMethod() async throws {
        let ehbpClient = try EHBPClient(
            baseURL: server.baseURL,
            publicKey: testPublicKey
        )

        do {
            _ = try await ehbpClient.request(
                method: "POST",
                path: "/v1/chat/completions",
                headers: [:],
                body: Data("{\"test\": true}".utf8)
            )
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "HTTP method should be preserved")
    }

    func testEHBPRequestPreservesURLPath() async throws {
        let ehbpClient = try EHBPClient(
            baseURL: server.baseURL,
            publicKey: testPublicKey
        )

        do {
            _ = try await ehbpClient.request(
                method: "POST",
                path: "/v1/chat/completions",
                headers: [:],
                body: Data("{\"test\": true}".utf8)
            )
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request URL was captured")
            return
        }

        XCTAssertEqual(capturedRequest.path, "/v1/chat/completions", "URL path should be preserved")
    }

    func testURLSessionInitializerValidatesConfigurationImmediately() {
        XCTAssertThrowsError(
            try EHBPURLSession(baseURL: "not a URL", publicKey: testPublicKey)
        )
        XCTAssertThrowsError(
            try EHBPURLSession(baseURL: server.baseURL, publicKey: Data(repeating: 0, count: 31))
        )
        XCTAssertThrowsError(
            try EHBPURLSessionFactory(
                baseURL: server.baseURL,
                publicKey: Data(repeating: 0, count: 31)
            )
        )
        XCTAssertThrowsError(
            try EHBPURLSession(baseURL: server.baseURL, enclaveURL: "not a URL", publicKey: testPublicKey)
        )
    }

    func testKeyMismatchRefreshesOnceAndReplaysWithNewEnclaveRoute() async throws {
        server.responseStatusCode = 422
        server.responseContentType = "application/problem+json"
        server.includeResponseNonce = false
        server.responseBody = Self.keyConfigProblemBody

        let refreshCounter = AsyncCounter()
        let session = EHBPURLSession(
            baseURL: server.baseURL,
            verifiedState: makeRotatingState(refreshCounter: refreshCounter)
        )
        var request = URLRequest(url: URL(string: "\(server.baseURL)/v1/chat/completions")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{}".utf8)

        do {
            _ = try await session.data(for: request, delegate: nil)
            XCTFail("The second key mismatch must be surfaced after one safe replay")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("still mismatched after refresh"))
        }

        let refreshCount = await refreshCounter.value
        XCTAssertEqual(refreshCount, 1)
        XCTAssertEqual(server.requestStore.requests.count, 2)
        XCTAssertEqual(enclaveRoutes(), ["https://old-router.example", "https://new-router.example"])
    }

    func testCancellingDuringTheRefreshPreventsTheReplay() async throws {
        server.responseStatusCode = 422
        server.responseContentType = "application/problem+json"
        server.includeResponseNonce = false
        server.responseBody = Self.keyConfigProblemBody

        let (state, refreshing, gate) = makeGatedRotatingState()
        let session = EHBPURLSession(baseURL: server.baseURL, verifiedState: state)
        var request = URLRequest(url: URL(string: "\(server.baseURL)/v1/chat/completions")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{}".utf8)

        let task = Task { try await session.data(for: request, delegate: nil) }
        await fulfillment(of: [refreshing], timeout: 2)
        // As when the user signs out while the request waits to be replayed
        task.cancel()
        await gate.open()

        do {
            _ = try await task.value
            XCTFail("a cancelled request must not be replayed")
        } catch is CancellationError {
        }
        XCTAssertEqual(server.requestStore.requests.count, 1, "The request was not replayed.")
    }

    func testCancellingAStreamingRequestDuringTheRefreshPreventsTheReplay() async throws {
        server.responseStatusCode = 422
        server.responseContentType = "application/problem+json"
        server.includeResponseNonce = false
        server.responseBody = Self.keyConfigProblemBody

        let (state, refreshing, gate) = makeGatedRotatingState()
        let completionCalled = expectation(description: "completion handler")
        let delegateCompleted = expectation(description: "delegate completion")
        let recorder = CancellationRecorder(
            completionCalled: completionCalled,
            delegateCompleted: delegateCompleted
        )
        let session = makeStreamingSession(delegate: recorder, verifiedState: state)
        var request = URLRequest(url: URL(string: "\(server.baseURL)/v1/chat/completions")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{}".utf8)
        let task = session.dataTask(with: request) { data, response, error in
            recorder.recordCompletion(data: data, response: response, error: error)
        }

        task.resume()
        await fulfillment(of: [refreshing], timeout: 2)
        task.cancel()
        await gate.open()
        await fulfillment(of: [completionCalled, delegateCompleted], timeout: 2)

        XCTAssertEqual(server.requestStore.requests.count, 1, "The request was not replayed.")
        XCTAssertEqual((recorder.completionError as? URLError)?.code, .cancelled)
        XCTAssertEqual(recorder.completionCount, 1)
    }

    // MARK: - Session Recovery Tokens

    private func pinnedSession() -> EHBPURLSession {
        EHBPURLSession(
            baseURL: server.baseURL,
            verifiedState: EHBPVerifiedState(
                endpoint: EHBPVerifiedEndpoint(enclaveURL: server.baseURL, publicKey: testPublicKey)
            )
        )
    }

    /// The encapsulated key each request the server received was sealed with
    private func encapsulatedKeys() -> [String] {
        server.requestStore.requests.compactMap { $0.headers[EHBPProtocol.encapsulatedKeyHeader] }
    }

    func testARecoverableResponseCarriesItsRequestsToken() async throws {
        server.responseContentType = "text/event-stream"
        server.responseBody = makeEncryptedResponse()

        let recoverable = try await pinnedSession().recoverableBytes(for: chatRequest())

        XCTAssertEqual(recoverable.response.statusCode, 200)
        let token = try XCTUnwrap(recoverable.recoveryToken)
        XCTAssertEqual(token.exportedSecret.count, EHBPConstants.exportLength)
        XCTAssertEqual([token.requestEnc.hexString], encapsulatedKeys(), "The token is for the request that was sent.")
        var body = Data()
        for try await chunk in recoverable.body {
            body.append(chunk)
        }
        XCTAssertEqual(body, Data(), "the fixture's encrypted stream decrypts to an empty body")
    }

    func testConcurrentRecoverableRequestsEachGetTheirOwnToken() async throws {
        server.responseContentType = "text/event-stream"
        server.responseBody = makeEncryptedResponse()
        let session = pinnedSession()

        async let first = session.recoverableBytes(for: chatRequest())
        async let second = session.recoverableBytes(for: chatRequest())
        let tokens = try await [first, second].map { try XCTUnwrap($0.recoveryToken).requestEnc.hexString }

        XCTAssertEqual(Set(tokens).count, 2)
        XCTAssertEqual(Set(tokens), Set(encapsulatedKeys()))
    }

    func testARecoverableRequestReplayedAfterAKeyRejectionCarriesTheReplaysToken() async throws {
        server.queuedResponses = [
            .init(statusCode: 422, contentType: "application/problem+json", body: Self.keyConfigProblemBody, includeNonce: false),
            .init(statusCode: 200, contentType: "text/event-stream", body: makeEncryptedResponse(), includeNonce: true),
        ]
        let session = EHBPURLSession(baseURL: server.baseURL, verifiedState: makeRotatingState(refreshCounter: AsyncCounter()))

        let recoverable = try await session.recoverableBytes(for: chatRequest())

        let keys = encapsulatedKeys()
        XCTAssertEqual(keys.count, 2)
        XCTAssertEqual(recoverable.recoveryToken?.requestEnc.hexString, keys.last)
    }

    func testAnUnsealedResponseHasNoToken() async throws {
        server.responseStatusCode = 401
        server.responseContentType = "text/plain"
        server.responseBody = Data("unauthorized".utf8)
        server.includeResponseNonce = false

        let recoverable = try await pinnedSession().recoverableBytes(for: chatRequest())

        XCTAssertEqual(recoverable.response.statusCode, 401)
        XCTAssertNil(recoverable.recoveryToken, "An intermediary's unencrypted error can't be recovered.")
        var body = Data()
        for try await chunk in recoverable.body {
            body.append(chunk)
        }
        XCTAssertEqual(body, Data("unauthorized".utf8))
    }

    /// A state whose refresh waits on the returned gate, fulfilling the
    /// returned expectation once it starts.
    private func makeGatedRotatingState() -> (EHBPVerifiedState, XCTestExpectation, AsyncGate) {
        let refreshing = expectation(description: "refreshing the rejected key")
        let gate = AsyncGate()
        let state = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(
                enclaveURL: "https://old-router.example",
                publicKey: testPublicKey
            ),
            refresh: { _ in
                refreshing.fulfill()
                await gate.wait()
                return EHBPVerifiedEndpoint(
                    enclaveURL: "https://new-router.example",
                    publicKey: Data(repeating: 0x43, count: 32)
                )
            }
        )
        return (state, refreshing, gate)
    }

    private static let keyConfigProblemBody = Data(
        "{\"type\":\"urn:ietf:params:ehbp:error:key-config\",\"title\":\"stale key\"}".utf8
    )

    private func makeRotatingState(refreshCounter: AsyncCounter) -> EHBPVerifiedState {
        EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(
                enclaveURL: "https://old-router.example",
                publicKey: testPublicKey
            ),
            refresh: { _ in
                await refreshCounter.increment()
                return EHBPVerifiedEndpoint(
                    enclaveURL: "https://new-router.example",
                    publicKey: Data(repeating: 0x43, count: 32)
                )
            }
        )
    }

    private func enclaveRoutes() -> [String] {
        server.requestStore.requests.compactMap { request in
            request.headers.first {
                $0.key.caseInsensitiveCompare(URLHelpers.enclaveURLHeaderName) == .orderedSame
            }?.value
        }
    }

    // MARK: - Attestation Freshness

    private static let oldRouter = "https://old-router.example"
    private static let newRouter = "https://new-router.example"

    private func makeExpiringState(
        clock: TestClock,
        expiresAt: Date,
        refreshCounter: AsyncCounter,
        refreshedExpiresAt: @escaping @Sendable () -> Date,
        beforeRefreshing: @escaping @Sendable () async -> Void = {},
        onClockRead: @escaping @Sendable () -> Void = {}
    ) -> EHBPVerifiedState {
        EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(
                enclaveURL: Self.oldRouter,
                publicKey: testPublicKey,
                expiresAt: expiresAt
            ),
            refresh: { _ in
                await refreshCounter.increment()
                await beforeRefreshing()
                return EHBPVerifiedEndpoint(
                    enclaveURL: Self.newRouter,
                    publicKey: Data(repeating: 0x43, count: 32),
                    expiresAt: refreshedExpiresAt()
                )
            },
            now: {
                onClockRead()
                return clock.now
            }
        )
    }

    func testUnexpiredEndpointIsUsedWithoutRefreshing() async throws {
        let clock = TestClock()
        let refreshCounter = AsyncCounter()
        let state = makeExpiringState(
            clock: clock,
            expiresAt: clock.now.addingTimeInterval(1),
            refreshCounter: refreshCounter,
            refreshedExpiresAt: { clock.now.addingTimeInterval(3600) }
        )

        let current = try await state.current()

        XCTAssertEqual(current.endpoint.enclaveURL, Self.oldRouter)
        let refreshCount = await refreshCounter.value
        XCTAssertEqual(refreshCount, 0)
    }

    func testExpiredEndpointIsRefreshedOnceForConcurrentRequests() async throws {
        let clock = TestClock()
        let refreshStarted = expectation(description: "refresh started")
        // Without single-flight every request starts a refresh; let the count
        // assertion below report that rather than an over-fulfilled expectation.
        refreshStarted.assertForOverFulfill = false
        // Each request reads the clock once before joining the refresh, and
        // again only after it ends, so five reads mean all five are waiting.
        let allChecked = expectation(description: "every request found the key expired")
        allChecked.expectedFulfillmentCount = 5
        allChecked.assertForOverFulfill = false
        let gate = AsyncGate()
        let refreshCounter = AsyncCounter()
        let state = makeExpiringState(
            clock: clock,
            expiresAt: clock.now,
            refreshCounter: refreshCounter,
            refreshedExpiresAt: { clock.now.addingTimeInterval(3600) },
            beforeRefreshing: {
                refreshStarted.fulfill()
                await gate.wait()
            },
            onClockRead: { allChecked.fulfill() }
        )

        let requests = (0..<5).map { _ in Task { try await state.current() } }
        await fulfillment(of: [refreshStarted, allChecked], timeout: 1)
        await gate.open()

        for request in requests {
            let current = try await request.value
            XCTAssertEqual(current.endpoint.enclaveURL, Self.newRouter)
        }
        let refreshCount = await refreshCounter.value
        XCTAssertEqual(refreshCount, 1, "Requests that find the key expired share one refresh.")
    }

    func testRefreshThatIsAlreadyExpiredFails() async {
        let clock = TestClock()
        let state = makeExpiringState(
            clock: clock,
            expiresAt: clock.now,
            refreshCounter: AsyncCounter(),
            refreshedExpiresAt: { clock.now }
        )

        do {
            _ = try await state.current()
            XCTFail("An expired refresh must not authorize a request")
        } catch TinfoilError.attestationError(let failure) {
            XCTAssertTrue(failure.message.contains("freshness deadline"))
        } catch {
            XCTFail("expected an attestation error, got \(error)")
        }
    }

    func testExpiredEndpointWithoutRefreshFails() async {
        let clock = TestClock()
        let state = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(enclaveURL: Self.oldRouter, publicKey: testPublicKey, expiresAt: clock.now),
            now: { clock.now }
        )

        do {
            _ = try await state.current()
            XCTFail("An expired key without a refresh must not authorize a request")
        } catch TinfoilError.configurationError {
        } catch {
            XCTFail("expected a configuration error, got \(error)")
        }
    }

    func testSessionsKeepTheSecretTheyAreGiven() {
        // Client resolves the secret once, and leaves it empty for an
        // enclave the handle names; the sessions must not resolve it again.
        let state = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(enclaveURL: server.baseURL, publicKey: testPublicKey, expiresAt: .distantFuture),
            refresh: nil
        )
        for secret in ["", "client-level"] {
            XCTAssertEqual(EHBPURLSession(baseURL: server.baseURL, verifiedState: state, userCacheSecret: secret).userCacheSecret, secret)
            XCTAssertEqual(EHBPURLSessionFactory(baseURL: server.baseURL, verifiedState: state, userCacheSecret: secret).userCacheSecret, secret)
        }
    }

    func testRefusesProtocolUpgradesAndTunnels() async {
        let state = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(enclaveURL: server.baseURL, publicKey: testPublicKey, expiresAt: .distantFuture),
            refresh: nil
        )
        let session = EHBPURLSession(baseURL: server.baseURL, verifiedState: state)
        var websocket = URLRequest(url: URL(string: "\(server.baseURL)/v1/realtime")!)
        websocket.setValue("websocket", forHTTPHeaderField: "upgrade")
        websocket.setValue("Upgrade", forHTTPHeaderField: "Connection")
        var tunnel = URLRequest(url: URL(string: "\(server.baseURL)/")!)
        tunnel.httpMethod = "CONNECT"

        for request in [websocket, tunnel] {
            do {
                _ = try await session.data(for: request, delegate: nil)
                XCTFail("\(request.httpMethod ?? "GET") \(request.url!) must be refused")
            } catch TinfoilError.configurationError(let failure) {
                XCTAssertTrue(failure.message.contains("protocol upgrade"), failure.message)
            } catch {
                XCTFail("expected a configuration error, got \(error)")
            }
        }
        XCTAssertTrue(server.requestStore.requests.isEmpty, "Nothing unsealed may leave the client.")
    }

    func testExpiredAttestationIsRefreshedBeforeTheRequestIsSent() async throws {
        let clock = TestClock()
        let refreshCounter = AsyncCounter()
        let state = makeExpiringState(
            clock: clock,
            expiresAt: clock.now.addingTimeInterval(60),
            refreshCounter: refreshCounter,
            refreshedExpiresAt: { clock.now.addingTimeInterval(3600) }
        )
        let session = EHBPURLSession(baseURL: server.baseURL, verifiedState: state)
        var request = URLRequest(url: URL(string: "\(server.baseURL)/v1/chat/completions")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{}".utf8)

        clock.advance(by: 60)
        // The stub cannot encrypt a response, so the request itself fails;
        // what matters is where it was sent.
        _ = try? await session.data(for: request, delegate: nil)

        let refreshCount = await refreshCounter.value
        XCTAssertEqual(refreshCount, 1)
        XCTAssertEqual(enclaveRoutes(), [Self.newRouter], "Nothing may be sealed to the expired key.")
    }

    func testStreamingKeyMismatchReplaysOnceAndDeliversOnlyReplayedResponse() async throws {
        server.queuedResponses = [
            .init(
                statusCode: 422,
                contentType: "application/problem+json",
                body: Self.keyConfigProblemBody,
                includeNonce: false
            ),
            .init(
                statusCode: 200,
                contentType: "text/event-stream",
                body: makeEncryptedResponse(),
                includeNonce: true
            )
        ]

        let refreshCounter = AsyncCounter()
        let recorder = StreamingRecorder()
        let session = makeStreamingSession(
            delegate: recorder,
            verifiedState: makeRotatingState(refreshCounter: refreshCounter)
        )
        var request = URLRequest(url: URL(string: "\(server.baseURL)/v1/chat/completions")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{}".utf8)

        let (data, response) = try await session.data(for: request, delegate: nil)
        await fulfillment(of: [recorder.delegateCompleted], timeout: 2)

        let refreshCount = await refreshCounter.value
        XCTAssertEqual(refreshCount, 1)
        XCTAssertEqual(enclaveRoutes(), ["https://old-router.example", "https://new-router.example"])
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
        XCTAssertEqual(data, Data(), "the fixture's encrypted stream decrypts to an empty body")
        XCTAssertEqual(recorder.responseStatusCodes, [200], "the rejected 422 must never reach the delegate")
        XCTAssertTrue(recorder.receivedData.isEmpty, "no bytes from the rejected 422 may leak to the delegate")
        XCTAssertEqual(recorder.completionCount, 1)
        XCTAssertNil(recorder.completionError)
    }

    /// Serves a 307 to `location`, as a server redirecting EHBP traffic
    private func redirect(to location: String) -> LocalTestServer.Response {
        LocalTestServer.Response(statusCode: 307, contentType: "text/plain", body: Data(), includeNonce: false, location: location)
    }

    private func chatRequest() -> URLRequest {
        var request = URLRequest(url: URL(string: "\(server.baseURL)/v1/chat/completions")!)
        request.httpMethod = "POST"
        request.setValue("custom-value", forHTTPHeaderField: "X-Custom")
        request.httpBody = Data("{}".utf8)
        return request
    }

    func testARedirectToAnotherOriginIsRefused() async throws {
        let elsewhere = LocalTestServer()
        try elsewhere.start()
        defer { elsewhere.stop() }
        server.queuedResponses = [redirect(to: "\(elsewhere.baseURL)/v1/chat/completions")]
        let session = EHBPURLSession(baseURL: server.baseURL, verifiedState: EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(enclaveURL: server.baseURL, publicKey: testPublicKey)
        ))

        do {
            _ = try await session.data(for: chatRequest(), delegate: nil)
            XCTFail("a redirect off the base URL's origin must not be followed")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains("refusing redirect"), failure.message)
        }
        XCTAssertTrue(elsewhere.requestStore.requests.isEmpty, "Nothing reaches the other origin.")
    }

    func testEHBPSessionsAreSharedPerOrigin() {
        let session = URLSession.ehbp(baseURL: "https://enclave.example")
        XCTAssertTrue(URLSession.ehbp(baseURL: "https://ENCLAVE.example:443/v1") === session, "One origin shares one session.")
        XCTAssertFalse(URLSession.ehbp(baseURL: "https://enclave.example:8443") === session)
    }

    func testARedirectWithinTheOriginIsFollowed() async throws {
        server.queuedResponses = [redirect(to: "/v1/moved")]
        let session = EHBPURLSession(baseURL: server.baseURL, verifiedState: EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(enclaveURL: server.baseURL, publicKey: testPublicKey)
        ))

        // The stub server can't seal a response, so the followed request
        // fails; what matters is that it was sent where it was redirected.
        _ = try? await session.data(for: chatRequest(), delegate: nil)

        XCTAssertEqual(server.requestStore.requests.map(\.path), ["/v1/chat/completions", "/v1/moved"])
    }

    func testAStreamingRedirectToAnotherOriginIsRefused() async throws {
        let elsewhere = LocalTestServer()
        try elsewhere.start()
        defer { elsewhere.stop() }
        server.queuedResponses = [redirect(to: "\(elsewhere.baseURL)/v1/chat/completions")]
        let recorder = StreamingRecorder()
        let session = makeStreamingSession(delegate: recorder)

        do {
            _ = try await session.data(for: chatRequest(), delegate: nil)
            XCTFail("a redirect off the base URL's origin must not be followed")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains("refusing redirect"), failure.message)
        }
        await fulfillment(of: [recorder.delegateCompleted], timeout: 2)
        XCTAssertTrue(recorder.responseStatusCodes.isEmpty, "The redirect response is not delivered.")
        XCTAssertTrue(elsewhere.requestStore.requests.isEmpty, "Nothing reaches the other origin.")
    }

    func testStreamingSecondKeyMismatchIsSurfacedWithoutDeliveringResponse() async throws {
        server.responseStatusCode = 422
        server.responseContentType = "application/problem+json"
        server.includeResponseNonce = false
        server.responseBody = Self.keyConfigProblemBody

        let refreshCounter = AsyncCounter()
        let recorder = StreamingRecorder()
        let session = makeStreamingSession(
            delegate: recorder,
            verifiedState: makeRotatingState(refreshCounter: refreshCounter)
        )
        var request = URLRequest(url: URL(string: "\(server.baseURL)/v1/chat/completions")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{}".utf8)

        do {
            _ = try await session.data(for: request, delegate: nil)
            XCTFail("The second key mismatch must be surfaced after one safe replay")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("still mismatched after refresh"))
        }
        await fulfillment(of: [recorder.delegateCompleted], timeout: 2)

        let refreshCount = await refreshCounter.value
        XCTAssertEqual(refreshCount, 1)
        XCTAssertEqual(server.requestStore.requests.count, 2)
        XCTAssertTrue(recorder.responseStatusCodes.isEmpty)
        XCTAssertTrue(recorder.receivedData.isEmpty)
        XCTAssertEqual(recorder.completionCount, 1)
        XCTAssertNotNil(recorder.completionError)
    }

    func testStreamingBoundedProblemThatIsNotKeyMismatchIsDeliveredIntact() async throws {
        let problem = Data("{\"type\":\"about:blank\",\"title\":\"bad request body\"}".utf8)
        server.responseStatusCode = 422
        server.responseContentType = "application/problem+json"
        server.includeResponseNonce = false
        server.responseBody = problem

        let refreshCounter = AsyncCounter()
        let recorder = StreamingRecorder()
        let session = makeStreamingSession(
            delegate: recorder,
            verifiedState: makeRotatingState(refreshCounter: refreshCounter)
        )
        var request = URLRequest(url: URL(string: "\(server.baseURL)/v1/chat/completions")!)
        request.httpMethod = "POST"
        request.httpBody = Data("{}".utf8)

        let (data, response) = try await session.data(for: request, delegate: nil)
        await fulfillment(of: [recorder.delegateCompleted], timeout: 2)

        let refreshCount = await refreshCounter.value
        XCTAssertEqual(refreshCount, 0, "a generic problem must not trigger attestation refresh")
        XCTAssertEqual(server.requestStore.requests.count, 1)
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 422)
        XCTAssertEqual(data, problem)
        XCTAssertEqual(recorder.responseStatusCodes, [422])
        XCTAssertEqual(recorder.receivedData, problem, "prefetched chunks must be replayed to the delegate")
        XCTAssertEqual(recorder.completionCount, 1)
    }

    func testCancelledRefreshWaiterDoesNotCancelOrBlockSharedRefresh() async throws {
        let refreshStarted = expectation(description: "shared refresh started")
        let cancelledWaiterFinished = expectation(description: "cancelled waiter finished")
        let gate = AsyncGate()
        let refreshCounter = AsyncCounter()
        let refreshedEndpoint = EHBPVerifiedEndpoint(
            enclaveURL: "https://new-router.example",
            publicKey: Data(repeating: 0x44, count: 32)
        )
        let state = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(
                enclaveURL: "https://old-router.example",
                publicKey: testPublicKey
            ),
            refresh: { _ in
                await refreshCounter.increment()
                refreshStarted.fulfill()
                await gate.wait()
                return refreshedEndpoint
            }
        )

        let cancelledWaiter = Task {
            defer { cancelledWaiterFinished.fulfill() }
            return try await state.refresh(afterRejectedGeneration: 0)
        }
        await fulfillment(of: [refreshStarted], timeout: 1)
        cancelledWaiter.cancel()
        await fulfillment(of: [cancelledWaiterFinished], timeout: 1)

        let survivingWaiter = Task {
            try await state.refresh(afterRejectedGeneration: 0)
        }
        await gate.open()

        do {
            _ = try await cancelledWaiter.value
            XCTFail("The cancelled waiter must return cancellation")
        } catch is CancellationError {
            // Expected: cancelling one waiter does not cancel shared refresh.
        }
        let refreshed = try await survivingWaiter.value
        let refreshCount = await refreshCounter.value
        XCTAssertEqual(refreshed.enclaveURL, refreshedEndpoint.enclaveURL)
        XCTAssertEqual(refreshCount, 1)
    }

    // MARK: - Encapsulated Key Format Tests

    func testEncapsulatedKeyIsValidHex() async throws {
        let ehbpClient = try EHBPClient(
            baseURL: server.baseURL,
            publicKey: testPublicKey
        )

        do {
            _ = try await ehbpClient.request(
                method: "POST",
                path: "/test",
                headers: [:],
                body: Data("test".utf8)
            )
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest,
              let keyHex = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader] else {
            XCTFail("Encapsulated key header not found")
            return
        }

        XCTAssertEqual(keyHex.count, 64, "X25519 encapsulated key should be 32 bytes = 64 hex chars")

        guard let keyData = Data(hexString: keyHex) else {
            XCTFail("Encapsulated key is not valid hex")
            return
        }

        XCTAssertEqual(keyData.count, 32, "Decoded key should be 32 bytes")
    }

    // MARK: - Streaming Request Tests

    func testEHBPStreamingRequestContainsEncapsulatedKeyHeader() async throws {
        let ehbpClient = try EHBPClient(
            baseURL: server.baseURL,
            publicKey: testPublicKey
        )

        let testBody = Data("{\"model\": \"gpt-oss-120b\", \"stream\": true}".utf8)

        do {
            let (stream, _) = try await ehbpClient.requestStream(
                method: "POST",
                path: "/v1/chat/completions",
                headers: ["Content-Type": "application/json"],
                body: testBody
            )
            for try await _ in stream {
                // Consume stream
            }
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured for streaming")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Streaming request should contain \(EHBPProtocol.encapsulatedKeyHeader) header")

        if let keyHex = encapsulatedKeyHeader {
            XCTAssertEqual(keyHex.count, 64, "Encapsulated key should be 32 bytes (64 hex chars)")
        }
    }

    func testEHBPStreamingRequestBodyIsEncrypted() async throws {
        let ehbpClient = try EHBPClient(
            baseURL: server.baseURL,
            publicKey: testPublicKey
        )

        let plainTextBody = """
        {
            "model": "gpt-oss-120b",
            "messages": [{"role": "user", "content": "Hello streaming!"}],
            "stream": true
        }
        """
        let testBody = Data(plainTextBody.utf8)

        do {
            let (stream, _) = try await ehbpClient.requestStream(
                method: "POST",
                path: "/v1/chat/completions",
                headers: ["Content-Type": "application/json"],
                body: testBody
            )
            for try await _ in stream {
                // Consume stream
            }
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest,
              let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured for streaming")
            return
        }

        XCTAssertNotEqual(capturedBody, testBody, "Streaming request body should be encrypted")

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("streaming"), "Encrypted body should not contain plaintext 'streaming'")
            XCTAssertFalse(bodyString.contains("gpt-oss-120b"), "Encrypted body should not contain plaintext 'gpt-oss-120b'")
        }
    }

    func testStreamingSessionOnlyBuffersResponsesForCompletionHandlers() throws {
        let delegate = NoopStreamingDelegate()
        let session = makeStreamingSession(delegate: delegate)
        let request = URLRequest(url: URL(string: "\(server.baseURL)/v1/chat/completions")!)

        let delegateDrivenTask = try XCTUnwrap(
            session.dataTask(with: request) as? EHBPStreamingDataTask
        )
        let completionHandlerTask = try XCTUnwrap(
            session.dataTask(with: request) { _, _, _ in } as? EHBPStreamingDataTask
        )

        XCTAssertFalse(
            delegateDrivenTask.accumulatesResponse,
            "Delegate-driven streaming tasks should not buffer the full response"
        )
        XCTAssertTrue(
            completionHandlerTask.accumulatesResponse,
            "Completion-handler tasks must buffer the response they deliver"
        )
    }

    func testStreamingCancellationDoesNotReturnPartialData() async throws {
        server.responseBody = Data("partial".utf8)
        let completionCalled = expectation(description: "completion handler")
        let delegateCompleted = expectation(description: "delegate completion")
        let recorder = CancellationRecorder(
            completionCalled: completionCalled,
            delegateCompleted: delegateCompleted
        )
        let session = makeStreamingSession(delegate: recorder)
        let request = URLRequest(url: URL(string: "\(server.baseURL)/v1/models")!)

        session.dataTask(with: request) { data, response, error in
            recorder.recordCompletion(data: data, response: response, error: error)
        }.resume()

        await fulfillment(of: [completionCalled, delegateCompleted], timeout: 2)

        XCTAssertEqual(recorder.receivedData, Data("partial".utf8))
        XCTAssertNil(recorder.completionData)
        XCTAssertNil(recorder.completionResponse)
        XCTAssertEqual((recorder.completionError as? URLError)?.code, .cancelled)
        XCTAssertEqual(recorder.completionCount, 1)
        XCTAssertEqual(recorder.delegateCompletionCount, 1)
    }

    func testStreamingTaskCancelledBeforeResumeNeverStartsRequest() async throws {
        let completionCalled = expectation(description: "completion handler")
        let delegateCompleted = expectation(description: "delegate completion")
        let recorder = CancellationRecorder(
            completionCalled: completionCalled,
            delegateCompleted: delegateCompleted
        )
        let session = makeStreamingSession(delegate: recorder)
        let request = URLRequest(url: URL(string: "\(server.baseURL)/v1/models")!)
        let task = session.dataTask(with: request) { data, response, error in
            recorder.recordCompletion(data: data, response: response, error: error)
        }

        task.cancel()
        task.resume()

        await fulfillment(of: [completionCalled, delegateCompleted], timeout: 2)

        XCTAssertTrue(server.requestStore.requests.isEmpty)
        XCTAssertNil(recorder.completionData)
        XCTAssertNil(recorder.completionResponse)
        XCTAssertEqual((recorder.completionError as? URLError)?.code, .cancelled)
        XCTAssertEqual(recorder.completionCount, 1)
        XCTAssertEqual(recorder.delegateCompletionCount, 1)
    }

    func testConcurrentStreamingResumeAndCancelCompletesOnce() async throws {
        let completionCalled = expectation(description: "completion handler")
        let delegateCompleted = expectation(description: "delegate completion")
        let recorder = CancellationRecorder(
            completionCalled: completionCalled,
            delegateCompleted: delegateCompleted
        )
        let session = makeStreamingSession(delegate: recorder)
        let request = URLRequest(url: URL(string: "\(server.baseURL)/v1/models")!)
        let task = session.dataTask(with: request) { data, response, error in
            recorder.recordCompletion(data: data, response: response, error: error)
        }

        await withTaskGroup(of: Void.self) { group in
            group.addTask { task.resume() }
            group.addTask { task.cancel() }
        }

        await fulfillment(of: [completionCalled, delegateCompleted], timeout: 2)

        XCTAssertNil(recorder.completionData)
        XCTAssertNil(recorder.completionResponse)
        XCTAssertEqual((recorder.completionError as? URLError)?.code, .cancelled)
        XCTAssertEqual(recorder.completionCount, 1)
        XCTAssertEqual(recorder.delegateCompletionCount, 1)
    }

    // MARK: - Protocol Constants Tests

    func testEHBPProtocolConstants() {
        XCTAssertEqual(
            EHBPProtocol.encapsulatedKeyHeader,
            "Ehbp-Encapsulated-Key",
            "Encapsulated key header name should match protocol spec"
        )
        XCTAssertEqual(
            EHBPProtocol.responseNonceHeader,
            "Ehbp-Response-Nonce",
            "Response nonce header name should match protocol spec"
        )
    }

    // MARK: - Client End-to-End Tests

    /// Verifies that Client.chats() uses EHBP encryption end-to-end
    func testClientChatsUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = ChatQuery(
            messages: [.user(.init(content: .string("Hello from Client test!")))],
            model: "gpt-oss-120b"
        )

        do {
            _ = try await client.chats(query: query)
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.chats()")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "Client.chats() should use POST")

        // Most important assertion: EHBP header MUST be present
        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.chats() request MUST have EHBP encapsulated key header - this proves EHBP is being used")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from Client.chats()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Hello from Client"), "Client.chats() body MUST be encrypted - found plaintext message")
            XCTAssertFalse(bodyString.contains("gpt-oss-120b"), "Client.chats() body MUST be encrypted - found plaintext model")
            XCTAssertFalse(bodyString.contains("messages"), "Client.chats() body MUST be encrypted - found plaintext 'messages'")
        }

        XCTAssertNotNil(capturedRequest.headers["Authorization"], "Client.chats() should include Authorization header")
    }

    /// Verifies that per-request headers reach the wire alongside the client's
    /// customHeaders, and override them on collision, through the EHBP transport.
    func testClientChatsForwardsPerRequestHeaders() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString,
            customHeaders: ["X-Configured": "config", "X-Both": "config"]
        )

        let query = ChatQuery(
            messages: [.user(.init(content: .string("headers test")))],
            model: "gpt-oss-120b"
        )

        do {
            _ = try await client.chats(
                query: query,
                headers: ["X-Tinfoil-Conversation-Id": "chat-123", "X-Both": "request"]
            )
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.chats(query:headers:)")
            return
        }
        XCTAssertEqual(capturedRequest.headers["X-Configured"], "config")
        XCTAssertEqual(capturedRequest.headers["X-Tinfoil-Conversation-Id"], "chat-123")
        XCTAssertEqual(capturedRequest.headers["X-Both"], "request")
        XCTAssertNotNil(capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader])
    }

    func testClientChatsStreamForwardsPerRequestHeaders() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString,
            customHeaders: ["X-Configured": "config", "X-Both": "config"]
        )

        let query = ChatQuery(
            messages: [.user(.init(content: .string("headers stream test")))],
            model: "gpt-oss-120b",
            stream: true
        )

        let stream = client.chatsStream(
            query: query,
            headers: ["X-Tinfoil-Conversation-Id": "chat-123", "X-Both": "request"]
        )
        do {
            for try await _ in stream {
                // Consume stream
            }
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.chatsStream(query:headers:)")
            return
        }
        XCTAssertEqual(capturedRequest.headers["X-Configured"], "config")
        XCTAssertEqual(capturedRequest.headers["X-Tinfoil-Conversation-Id"], "chat-123")
        XCTAssertEqual(capturedRequest.headers["X-Both"], "request")
        XCTAssertNotNil(capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader])
    }

    /// Verifies that Client.chatsStream() uses EHBP encryption end-to-end
    func testClientChatsStreamUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = ChatQuery(
            messages: [.user(.init(content: .string("Hello streaming from Client!")))],
            model: "gpt-oss-120b",
            stream: true
        )

        let stream = client.chatsStream(query: query)

        do {
            for try await _ in stream {
                // Consume stream
            }
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.chatsStream()")
            return
        }

        // Most important assertion: EHBP header MUST be present
        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.chatsStream() request MUST have EHBP encapsulated key header - this proves EHBP is being used")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from Client.chatsStream()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Hello streaming from Client"), "Client.chatsStream() body MUST be encrypted")
            XCTAssertFalse(bodyString.contains("gpt-oss-120b"), "Client.chatsStream() body MUST be encrypted")
        }
    }

    /// Verifies that Client.embeddings() uses EHBP encryption end-to-end
    func testClientEmbeddingsUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = EmbeddingsQuery(
            input: .string("The quick brown fox jumps over the lazy dog"),
            model: "text-embedding-ada-002"
        )

        do {
            _ = try await client.embeddings(query: query)
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.embeddings()")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "Client.embeddings() should use POST")

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.embeddings() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from Client.embeddings()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("quick brown fox"), "Client.embeddings() body MUST be encrypted")
            XCTAssertFalse(bodyString.contains("text-embedding"), "Client.embeddings() body MUST be encrypted")
        }
    }

    /// Verifies that Client.images() uses EHBP encryption end-to-end
    func testClientImagesUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = ImagesQuery(
            prompt: "A beautiful sunset over the ocean",
            model: "dall-e-3"
        )

        do {
            _ = try await client.images(query: query)
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.images()")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "Client.images() should use POST")

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.images() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from Client.images()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("beautiful sunset"), "Client.images() body MUST be encrypted")
            XCTAssertFalse(bodyString.contains("dall-e"), "Client.images() body MUST be encrypted")
        }
    }

    /// Verifies that Client.createResponse() (Responses API) uses EHBP encryption end-to-end
    func testClientCreateResponseUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = CreateModelResponseQuery(
            input: .textInput("Hello from Responses API test!"),
            model: "gpt-oss-120b"
        )

        do {
            _ = try await client.createResponse(query: query)
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.createResponse()")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "Client.createResponse() should use POST")

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.createResponse() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from Client.createResponse()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Responses API test"), "Client.createResponse() body MUST be encrypted")
            XCTAssertFalse(bodyString.contains("gpt-oss-120b"), "Client.createResponse() body MUST be encrypted")
        }
    }

    /// Verifies that Client.createResponseStream() (Responses API streaming) uses EHBP encryption end-to-end
    func testClientCreateResponseStreamUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = CreateModelResponseQuery(
            input: .textInput("Hello streaming from Responses API!"),
            model: "gpt-oss-120b",
            stream: true
        )

        let stream = client.createResponseStream(query: query)

        do {
            for try await _ in stream {
                // Consume stream
            }
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.createResponseStream()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.createResponseStream() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from Client.createResponseStream()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("streaming from Responses API"), "Client.createResponseStream() body MUST be encrypted")
            XCTAssertFalse(bodyString.contains("gpt-oss-120b"), "Client.createResponseStream() body MUST be encrypted")
        }
    }

    /// Verifies that Client.moderations() uses EHBP encryption end-to-end
    func testClientModerationsUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = ModerationsQuery(input: "This is a test message for content moderation")

        do {
            _ = try await client.moderations(query: query)
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.moderations()")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "Client.moderations() should use POST")

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.moderations() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from Client.moderations()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("content moderation"), "Client.moderations() body MUST be encrypted")
        }
    }

    /// Verifies that Client.imageEdits() uses EHBP encryption end-to-end
    func testClientImageEditsUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = ImageEditsQuery(
            image: Data("fake-image-data".utf8),
            prompt: "Add a rainbow to the sky"
        )

        do {
            _ = try await client.imageEdits(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.imageEdits()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.imageEdits() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that Client.imageVariations() uses EHBP encryption end-to-end
    func testClientImageVariationsUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = ImageVariationsQuery(image: Data("fake-image-data".utf8))

        do {
            _ = try await client.imageVariations(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.imageVariations()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.imageVariations() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that Client.audioCreateSpeech() uses EHBP encryption end-to-end
    func testClientAudioCreateSpeechUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = AudioSpeechQuery(
            model: .tts_1,
            input: "Hello, this is a test of text to speech",
            voice: .alloy
        )

        do {
            _ = try await client.audioCreateSpeech(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.audioCreateSpeech()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.audioCreateSpeech() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("text to speech"), "Client.audioCreateSpeech() body MUST be encrypted")
        }
    }

    /// Verifies that Client.audioTranscriptions() uses EHBP encryption end-to-end
    func testClientAudioTranscriptionsUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = AudioTranscriptionQuery(
            file: Data("fake-audio-data".utf8),
            fileType: .mp3,
            model: .whisper_1
        )

        do {
            _ = try await client.audioTranscriptions(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.audioTranscriptions()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.audioTranscriptions() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that Client.audioTranslations() uses EHBP encryption end-to-end
    func testClientAudioTranslationsUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = AudioTranslationQuery(
            file: Data("fake-audio-data".utf8),
            fileType: .mp3,
            model: .whisper_1
        )

        do {
            _ = try await client.audioTranslations(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.audioTranslations()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.audioTranslations() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that Client.assistantCreate() uses EHBP encryption end-to-end
    func testClientAssistantCreateUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = AssistantsQuery(
            model: "gpt-oss-120b",
            name: "Test Assistant",
            description: "A test assistant for EHBP verification",
            instructions: "You are a helpful test assistant",
            tools: nil
        )

        do {
            _ = try await client.assistantCreate(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.assistantCreate()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.assistantCreate() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("helpful test assistant"), "Client.assistantCreate() body MUST be encrypted")
        }
    }

    /// Verifies that Client.threads() uses EHBP encryption end-to-end
    func testClientThreadsUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let userMessage = ChatQuery.ChatCompletionMessageParam.UserMessageParam(
            content: .string("Secret thread creation message")
        )
        let query = ThreadsQuery(messages: [.user(userMessage)])

        do {
            _ = try await client.threads(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.threads()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.threads() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that Client.threadRun() uses EHBP encryption end-to-end
    func testClientThreadRunUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let threadRunUserMessage = ChatQuery.ChatCompletionMessageParam.UserMessageParam(
            content: .string("Hello from thread run test")
        )
        let query = ThreadRunQuery(
            assistantId: "test-assistant-id",
            thread: ThreadsQuery(messages: [.user(threadRunUserMessage)])
        )

        do {
            _ = try await client.threadRun(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.threadRun()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.threadRun() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("thread run test"), "Client.threadRun() body MUST be encrypted")
        }
    }

    /// Verifies that Client.runs() uses EHBP encryption end-to-end
    func testClientRunsUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = RunsQuery(assistantId: "test-assistant-id")

        do {
            _ = try await client.runs(threadId: "test-thread-id", query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.runs()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.runs() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that Client.threadsAddMessage() uses EHBP encryption end-to-end
    func testClientThreadsAddMessageUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = MessageQuery(role: .user, content: "Secret message for the thread")

        do {
            _ = try await client.threadsAddMessage(threadId: "test-thread-id", query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.threadsAddMessage()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.threadsAddMessage() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Secret message"), "Client.threadsAddMessage() body MUST be encrypted")
        }
    }

    /// Verifies that Client.files() uses EHBP encryption end-to-end
    func testClientFilesUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = FilesQuery(
            purpose: "assistants",
            file: Data("secret file contents".utf8),
            fileName: "test.txt",
            contentType: "text/plain"
        )

        do {
            _ = try await client.files(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.files()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.files() request MUST have EHBP encapsulated key header")
    }

    // MARK: - Architectural Guarantee Tests

    /// Verifies that Client CANNOT be created without an HPKE public key
    /// This ensures EHBP is mandatory - there's no way to bypass it
    func testClientRequiresHPKEKey() {
        XCTAssertThrowsError(
            try Client(
                apiKey: "test-api-key",
                baseURL: "https://example.com",
                enclaveURL: "https://example.com",
                hpkePublicKeyHex: nil
            ),
            "Client should throw when HPKE key is nil"
        ) { error in
            guard let tinfoilError = error as? TinfoilError else {
                XCTFail("Expected TinfoilError, got \(error)")
                return
            }
            if case .attestationError(let failure) = tinfoilError {
                XCTAssertTrue(failure.message.contains("EHBP") || failure.message.contains("HPKE"), "Error should mention EHBP or HPKE")
            } else {
                XCTFail("Expected attestationError, as an attestation that endorses no HPKE key")
            }
        }
    }

    /// Verifies that Client CANNOT be created with an empty HPKE public key
    func testClientRejectsEmptyHPKEKey() {
        XCTAssertThrowsError(
            try Client(
                apiKey: "test-api-key",
                baseURL: "https://example.com",
                enclaveURL: "https://example.com",
                hpkePublicKeyHex: ""
            ),
            "Client should throw when HPKE key is empty"
        ) { error in
            guard let tinfoilError = error as? TinfoilError else {
                XCTFail("Expected TinfoilError, got \(error)")
                return
            }
            if case .attestationError = tinfoilError {
                // Expected
            } else {
                XCTFail("Expected attestationError, as an attestation that endorses no HPKE key")
            }
        }
    }

    /// Verifies that ALL Client POST requests have non-empty bodies.
    /// This is critical because EHBPClient skips encryption when body is empty:
    /// `if let body = body, !body.isEmpty { ... }`
    /// An empty body would bypass EHBP encryption entirely.
    func testAllPOSTRequestsHaveNonEmptyBodies() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        // Track all POST requests and verify they have non-empty bodies
        var testedEndpoints: [(name: String, hasBody: Bool)] = []

        // Helper to test an endpoint
        func testEndpoint(_ name: String, action: () async throws -> Void) async {
            server.requestStore.clear()
            do {
                try await action()
            } catch {
                // Expected - server returns invalid response
            }
            try? await Task.sleep(nanoseconds: 50_000_000)

            if let request = server.requestStore.lastRequest {
                let hasBody = request.body != nil && !request.body!.isEmpty
                testedEndpoints.append((name, hasBody))
            }
        }

        // Helper for streaming endpoints
        func testStreamingEndpoint<T>(_ name: String, stream: AsyncThrowingStream<T, Error>) async {
            server.requestStore.clear()
            do {
                for try await _ in stream {
                    break
                }
            } catch {
                // Expected
            }
            try? await Task.sleep(nanoseconds: 50_000_000)

            if let request = server.requestStore.lastRequest {
                let hasBody = request.body != nil && !request.body!.isEmpty
                testedEndpoints.append((name, hasBody))
            }
        }

        // Test all POST endpoints
        await testEndpoint("chats") {
            _ = try await client.chats(query: ChatQuery(
                messages: [.user(.init(content: .string("test")))],
                model: "gpt-oss-120b"
            ))
        }

        await testStreamingEndpoint("chatsStream", stream: client.chatsStream(query: ChatQuery(
            messages: [.user(.init(content: .string("test")))],
            model: "gpt-oss-120b",
            stream: true
        )))

        await testEndpoint("embeddings") {
            _ = try await client.embeddings(query: EmbeddingsQuery(
                input: .string("test"),
                model: "text-embedding-ada-002"
            ))
        }

        await testEndpoint("images") {
            _ = try await client.images(query: ImagesQuery(prompt: "test"))
        }

        await testEndpoint("imageEdits") {
            _ = try await client.imageEdits(query: ImageEditsQuery(
                image: Data("fake".utf8),
                prompt: "test"
            ))
        }

        await testEndpoint("imageVariations") {
            _ = try await client.imageVariations(query: ImageVariationsQuery(
                image: Data("fake".utf8)
            ))
        }

        await testEndpoint("moderations") {
            _ = try await client.moderations(query: ModerationsQuery(input: "test"))
        }

        await testEndpoint("audioCreateSpeech") {
            _ = try await client.audioCreateSpeech(query: AudioSpeechQuery(
                model: .tts_1,
                input: "test",
                voice: .alloy
            ))
        }

        await testStreamingEndpoint("audioCreateSpeechStream", stream: client.audioCreateSpeechStream(query: AudioSpeechQuery(
            model: .tts_1,
            input: "test",
            voice: .alloy
        )))

        await testEndpoint("audioTranscriptions") {
            _ = try await client.audioTranscriptions(query: AudioTranscriptionQuery(
                file: Data("fake".utf8),
                fileType: .mp3,
                model: .whisper_1
            ))
        }

        await testEndpoint("audioTranslations") {
            _ = try await client.audioTranslations(query: AudioTranslationQuery(
                file: Data("fake".utf8),
                fileType: .mp3,
                model: .whisper_1
            ))
        }

        await testEndpoint("assistantCreate") {
            _ = try await client.assistantCreate(query: AssistantsQuery(
                model: "gpt-oss-120b",
                name: "test",
                description: nil,
                instructions: nil,
                tools: nil
            ))
        }

        await testEndpoint("assistantModify") {
            _ = try await client.assistantModify(
                query: AssistantsQuery(
                    model: "gpt-oss-120b",
                    name: "test",
                    description: nil,
                    instructions: nil,
                    tools: nil
                ),
                assistantId: "asst_123"
            )
        }

        await testEndpoint("threads") {
            _ = try await client.threads(query: ThreadsQuery(messages: []))
        }

        await testEndpoint("threadRun") {
            _ = try await client.threadRun(query: ThreadRunQuery(
                assistantId: "asst_123",
                thread: ThreadsQuery(messages: [])
            ))
        }

        await testEndpoint("runs") {
            _ = try await client.runs(
                threadId: "thread_123",
                query: RunsQuery(assistantId: "asst_123")
            )
        }

        await testEndpoint("runSubmitToolOutputs") {
            _ = try await client.runSubmitToolOutputs(
                threadId: "thread_123",
                runId: "run_456",
                query: RunToolOutputsQuery(toolOutputs: [
                    .init(toolCallId: "call_123", output: "result")
                ])
            )
        }

        await testEndpoint("threadsAddMessage") {
            _ = try await client.threadsAddMessage(
                threadId: "thread_123",
                query: MessageQuery(role: .user, content: "test")
            )
        }

        await testEndpoint("files") {
            _ = try await client.files(query: FilesQuery(
                purpose: "assistants",
                file: Data("test".utf8),
                fileName: "test.txt",
                contentType: "text/plain"
            ))
        }

        await testEndpoint("createResponse") {
            _ = try await client.createResponse(query: CreateModelResponseQuery(
                input: .textInput("test"),
                model: "gpt-oss-120b"
            ))
        }

        await testStreamingEndpoint("createResponseStream", stream: client.createResponseStream(query: CreateModelResponseQuery(
            input: .textInput("test"),
            model: "gpt-oss-120b",
            stream: true
        )))

        // Verify ALL endpoints have non-empty bodies
        var failures: [String] = []
        for (name, hasBody) in testedEndpoints {
            if !hasBody {
                failures.append(name)
            }
        }

        XCTAssertTrue(
            failures.isEmpty,
            "SECURITY FAILURE: The following POST endpoints have empty bodies and would bypass EHBP encryption: \(failures.joined(separator: ", "))"
        )

        // Also verify we tested a reasonable number of endpoints
        XCTAssertGreaterThanOrEqual(
            testedEndpoints.count,
            15,
            "Expected to test at least 15 POST endpoints, but only tested \(testedEndpoints.count)"
        )
    }

    /// Verifies that Client.audioCreateSpeechStream() uses EHBP encryption end-to-end
    func testClientAudioCreateSpeechStreamUsesEHBPEncryption() async throws {
        server.responseContentType = "audio/mpeg"
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = AudioSpeechQuery(
            model: .tts_1,
            input: "Secret streaming speech input",
            voice: .alloy
        )

        let stream = client.audioCreateSpeechStream(query: query)
        do {
            for try await _ in stream {
                XCTFail("The empty fixture must not yield audio")
            }
            XCTFail("Expected the empty-audio response to fail")
        } catch OpenAIError.emptyData {
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.audioCreateSpeechStream()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.audioCreateSpeechStream() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Secret streaming speech input"), "Client.audioCreateSpeechStream() body MUST be encrypted")
        }
    }

    /// Verifies that Client.audioTranscriptionsVerbose() uses EHBP encryption end-to-end
    func testClientAudioTranscriptionsVerboseUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = AudioTranscriptionQuery(
            file: Data("fake-audio-for-verbose-transcription".utf8),
            fileType: .mp3,
            model: .whisper_1,
            responseFormat: .verboseJson
        )

        do {
            _ = try await client.audioTranscriptionsVerbose(query: query)
        } catch {
            // Expected - server returns invalid response
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.audioTranscriptionsVerbose()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.audioTranscriptionsVerbose() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that Client.audioTranscriptionStream() uses EHBP encryption end-to-end
    func testClientAudioTranscriptionStreamUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = AudioTranscriptionQuery(
            file: Data("fake-audio-for-streaming-transcription".utf8),
            fileType: .mp3,
            model: .whisper_1
        )

        let stream = client.audioTranscriptionStream(query: query)
        for try await _ in stream {
            break
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.audioTranscriptionStream()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.audioTranscriptionStream() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that Client.assistantModify() uses EHBP encryption end-to-end
    func testClientAssistantModifyUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = AssistantsQuery(
            model: "gpt-oss-120b",
            name: "Modified Assistant",
            description: "Updated description",
            instructions: "Updated secret instructions",
            tools: nil
        )

        do {
            _ = try await client.assistantModify(query: query, assistantId: "asst_123")
        } catch {
            // Expected - server returns invalid response
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.assistantModify()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.assistantModify() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Updated secret instructions"), "Client.assistantModify() body MUST be encrypted")
        }
    }

    /// Verifies that Client.runSubmitToolOutputs() uses EHBP encryption end-to-end
    func testClientRunSubmitToolOutputsUsesEHBPEncryption() async throws {
        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = RunToolOutputsQuery(
            toolOutputs: [
                .init(toolCallId: "call_123", output: "Secret tool output result")
            ]
        )

        do {
            _ = try await client.runSubmitToolOutputs(threadId: "thread_123", runId: "run_456", query: query)
        } catch {
            // Expected - server returns invalid response
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from Client.runSubmitToolOutputs()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "Client.runSubmitToolOutputs() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Secret tool output result"), "Client.runSubmitToolOutputs() body MUST be encrypted")
        }
    }

    // MARK: - Helpers

    /// Creates a minimal encrypted response structure for testing
    /// This is not cryptographically valid but allows the test to proceed
    private func makeEncryptedResponse() -> Data {
        var data = Data()
        let chunkLength: UInt32 = 0
        data.append(contentsOf: withUnsafeBytes(of: chunkLength.bigEndian) { Array($0) })
        return data
    }
}

private actor AsyncCounter {
    private(set) var value = 0

    func increment() {
        value += 1
    }
}

/// A clock tests move by hand.
private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current = Date(timeIntervalSince1970: 1_790_000_000)

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    func advance(by seconds: TimeInterval) {
        lock.lock()
        current += seconds
        lock.unlock()
    }
}

// MARK: - Test Doubles

private final class CancellationRecorder: URLSessionDataDelegateProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private let completionCalled: XCTestExpectation
    private let delegateCompleted: XCTestExpectation
    private var cancelled = false
    private var _receivedData = Data()
    private var _completionData: Data?
    private var _completionResponse: URLResponse?
    private var _completionError: Error?
    private var _completionCount = 0
    private var _delegateCompletionCount = 0

    var receivedData: Data {
        lock.lock()
        defer { lock.unlock() }
        return _receivedData
    }

    var completionData: Data? {
        lock.lock()
        defer { lock.unlock() }
        return _completionData
    }

    var completionResponse: URLResponse? {
        lock.lock()
        defer { lock.unlock() }
        return _completionResponse
    }

    var completionError: Error? {
        lock.lock()
        defer { lock.unlock() }
        return _completionError
    }

    var completionCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _completionCount
    }

    var delegateCompletionCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _delegateCompletionCount
    }

    init(
        completionCalled: XCTestExpectation,
        delegateCompleted: XCTestExpectation
    ) {
        self.completionCalled = completionCalled
        self.delegateCompleted = delegateCompleted
    }

    func recordCompletion(data: Data?, response: URLResponse?, error: Error?) {
        lock.lock()
        _completionData = data
        _completionResponse = response
        _completionError = error
        _completionCount += 1
        let shouldFulfill = _completionCount == 1
        lock.unlock()
        if shouldFulfill {
            completionCalled.fulfill()
        }
    }

    func urlSession(_ session: URLSessionProtocol, task: URLSessionTaskProtocol, didCompleteWithError error: Error?) {
        lock.lock()
        _delegateCompletionCount += 1
        let shouldFulfill = _delegateCompletionCount == 1
        lock.unlock()
        if shouldFulfill {
            delegateCompleted.fulfill()
        }
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {}

    func urlSession(_ session: URLSessionProtocol, dataTask: URLSessionDataTaskProtocol, didReceive data: Data) {
        lock.lock()
        _receivedData.append(data)
        let shouldCancel = !cancelled
        cancelled = true
        lock.unlock()
        if shouldCancel {
            dataTask.cancel()
        }
    }

    func urlSession(
        _ session: URLSessionProtocol,
        dataTask: URLSessionDataTaskProtocol,
        didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        completionHandler(.allow)
    }
}

/// Records every delegate callback so tests can assert exactly which responses
/// and chunks a streaming consumer observed.
private final class StreamingRecorder: URLSessionDataDelegateProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var _responseStatusCodes: [Int] = []
    private var _receivedData = Data()
    private var _completionCount = 0
    private var _completionError: Error?
    /// The task's completion handler resumes the awaiting caller before the
    /// delegate completion callback runs, so tests must await this before
    /// asserting on completion state.
    let delegateCompleted = XCTestExpectation(description: "delegate completion")

    var responseStatusCodes: [Int] {
        lock.lock()
        defer { lock.unlock() }
        return _responseStatusCodes
    }

    var receivedData: Data {
        lock.lock()
        defer { lock.unlock() }
        return _receivedData
    }

    var completionCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _completionCount
    }

    var completionError: Error? {
        lock.lock()
        defer { lock.unlock() }
        return _completionError
    }

    func urlSession(_ session: URLSessionProtocol, task: URLSessionTaskProtocol, didCompleteWithError error: Error?) {
        lock.lock()
        _completionCount += 1
        _completionError = error
        lock.unlock()
        delegateCompleted.fulfill()
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {}

    func urlSession(_ session: URLSessionProtocol, dataTask: URLSessionDataTaskProtocol, didReceive data: Data) {
        lock.lock()
        _receivedData.append(data)
        lock.unlock()
    }

    func urlSession(
        _ session: URLSessionProtocol,
        dataTask: URLSessionDataTaskProtocol,
        didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        lock.lock()
        _responseStatusCodes.append((response as? HTTPURLResponse)?.statusCode ?? -1)
        lock.unlock()
        completionHandler(.allow)
    }
}

/// Delegate stub for constructing streaming sessions without a real SDK consumer
private final class NoopStreamingDelegate: URLSessionDataDelegateProtocol {
    func urlSession(_ session: URLSessionProtocol, task: URLSessionTaskProtocol, didCompleteWithError error: Error?) {}

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {}

    func urlSession(_ session: URLSessionProtocol, dataTask: URLSessionDataTaskProtocol, didReceive data: Data) {}

    func urlSession(
        _ session: URLSessionProtocol,
        dataTask: URLSessionDataTaskProtocol,
        didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {}
}

// MARK: - Extensions

extension Character {
    var isHexDigit: Bool {
        return "0123456789abcdefABCDEF".contains(self)
    }
}
