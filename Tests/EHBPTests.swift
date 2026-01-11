import XCTest
import Foundation
import OpenAI
import EHBP
@testable import TinfoilAI

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

    var responseNonce: String = Data(repeating: 0xAB, count: 32).hexString
    var responseBody: Data = Data()
    var responseStatusCode: Int = 200

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

        if let request = parseHTTPRequest(allData) {
            requestStore.append(request)
        }

        let response = buildHTTPResponse()
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

    private func buildHTTPResponse() -> Data {
        var response = "HTTP/1.1 \(responseStatusCode) OK\r\n"
        response += "Content-Type: application/json\r\n"
        response += "\(EHBPProtocol.responseNonceHeader): \(responseNonce)\r\n"
        response += "Content-Length: \(responseBody.count)\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"

        var responseData = Data(response.utf8)
        responseData.append(responseBody)
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
            "model": "gpt-4",
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

        let testBody = Data("{\"model\": \"gpt-4\", \"stream\": true}".utf8)

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
            "model": "gpt-4",
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
            XCTAssertFalse(bodyString.contains("gpt-4"), "Encrypted body should not contain plaintext 'gpt-4'")
        }
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

    // MARK: - TinfoilAI End-to-End Tests

    /// Verifies that TinfoilAI.chats() uses EHBP encryption end-to-end
    func testTinfoilAIChatsUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = ChatQuery(
            messages: [.user(.init(content: .string("Hello from TinfoilAI test!")))],
            model: "gpt-4"
        )

        do {
            _ = try await tinfoilClient.chats(query: query)
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.chats()")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "TinfoilAI.chats() should use POST")

        // Most important assertion: EHBP header MUST be present
        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.chats() request MUST have EHBP encapsulated key header - this proves EHBP is being used")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from TinfoilAI.chats()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Hello from TinfoilAI"), "TinfoilAI.chats() body MUST be encrypted - found plaintext message")
            XCTAssertFalse(bodyString.contains("gpt-4"), "TinfoilAI.chats() body MUST be encrypted - found plaintext model")
            XCTAssertFalse(bodyString.contains("messages"), "TinfoilAI.chats() body MUST be encrypted - found plaintext 'messages'")
        }

        XCTAssertNotNil(capturedRequest.headers["Authorization"], "TinfoilAI.chats() should include Authorization header")
    }

    /// Verifies that TinfoilAI.chatsStream() uses EHBP encryption end-to-end
    func testTinfoilAIChatsStreamUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = ChatQuery(
            messages: [.user(.init(content: .string("Hello streaming from TinfoilAI!")))],
            model: "gpt-4",
            stream: true
        )

        let stream = tinfoilClient.chatsStream(query: query)

        do {
            for try await _ in stream {
                // Consume stream
            }
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.chatsStream()")
            return
        }

        // Most important assertion: EHBP header MUST be present
        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.chatsStream() request MUST have EHBP encapsulated key header - this proves EHBP is being used")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from TinfoilAI.chatsStream()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Hello streaming from TinfoilAI"), "TinfoilAI.chatsStream() body MUST be encrypted")
            XCTAssertFalse(bodyString.contains("gpt-4"), "TinfoilAI.chatsStream() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.embeddings() uses EHBP encryption end-to-end
    func testTinfoilAIEmbeddingsUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.embeddings(query: query)
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.embeddings()")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "TinfoilAI.embeddings() should use POST")

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.embeddings() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from TinfoilAI.embeddings()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("quick brown fox"), "TinfoilAI.embeddings() body MUST be encrypted")
            XCTAssertFalse(bodyString.contains("text-embedding"), "TinfoilAI.embeddings() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.images() uses EHBP encryption end-to-end
    func testTinfoilAIImagesUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.images(query: query)
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.images()")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "TinfoilAI.images() should use POST")

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.images() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from TinfoilAI.images()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("beautiful sunset"), "TinfoilAI.images() body MUST be encrypted")
            XCTAssertFalse(bodyString.contains("dall-e"), "TinfoilAI.images() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.createResponse() (Responses API) uses EHBP encryption end-to-end
    func testTinfoilAICreateResponseUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = CreateModelResponseQuery(
            input: .textInput("Hello from Responses API test!"),
            model: "gpt-4"
        )

        do {
            _ = try await tinfoilClient.createResponse(query: query)
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.createResponse()")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "TinfoilAI.createResponse() should use POST")

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.createResponse() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from TinfoilAI.createResponse()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Responses API test"), "TinfoilAI.createResponse() body MUST be encrypted")
            XCTAssertFalse(bodyString.contains("gpt-4"), "TinfoilAI.createResponse() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.createResponseStream() (Responses API streaming) uses EHBP encryption end-to-end
    func testTinfoilAICreateResponseStreamUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = CreateModelResponseQuery(
            input: .textInput("Hello streaming from Responses API!"),
            model: "gpt-4",
            stream: true
        )

        let stream = tinfoilClient.createResponseStream(query: query)

        do {
            for try await _ in stream {
                // Consume stream
            }
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.createResponseStream()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.createResponseStream() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from TinfoilAI.createResponseStream()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("streaming from Responses API"), "TinfoilAI.createResponseStream() body MUST be encrypted")
            XCTAssertFalse(bodyString.contains("gpt-4"), "TinfoilAI.createResponseStream() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.moderations() uses EHBP encryption end-to-end
    func testTinfoilAIModerationsUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = ModerationsQuery(input: "This is a test message for content moderation")

        do {
            _ = try await tinfoilClient.moderations(query: query)
        } catch {
            // Expected to fail since our mock response is not properly encrypted
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.moderations()")
            return
        }

        XCTAssertEqual(capturedRequest.method, "POST", "TinfoilAI.moderations() should use POST")

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.moderations() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured from TinfoilAI.moderations()")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("content moderation"), "TinfoilAI.moderations() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.imageEdits() uses EHBP encryption end-to-end
    func testTinfoilAIImageEditsUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.imageEdits(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.imageEdits()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.imageEdits() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that TinfoilAI.imageVariations() uses EHBP encryption end-to-end
    func testTinfoilAIImageVariationsUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = ImageVariationsQuery(image: Data("fake-image-data".utf8))

        do {
            _ = try await tinfoilClient.imageVariations(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.imageVariations()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.imageVariations() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that TinfoilAI.audioCreateSpeech() uses EHBP encryption end-to-end
    func testTinfoilAIAudioCreateSpeechUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.audioCreateSpeech(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.audioCreateSpeech()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.audioCreateSpeech() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("text to speech"), "TinfoilAI.audioCreateSpeech() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.audioTranscriptions() uses EHBP encryption end-to-end
    func testTinfoilAIAudioTranscriptionsUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.audioTranscriptions(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.audioTranscriptions()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.audioTranscriptions() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that TinfoilAI.audioTranslations() uses EHBP encryption end-to-end
    func testTinfoilAIAudioTranslationsUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.audioTranslations(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.audioTranslations()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.audioTranslations() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that TinfoilAI.assistantCreate() uses EHBP encryption end-to-end
    func testTinfoilAIAssistantCreateUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = AssistantsQuery(
            model: "gpt-4",
            name: "Test Assistant",
            description: "A test assistant for EHBP verification",
            instructions: "You are a helpful test assistant",
            tools: nil
        )

        do {
            _ = try await tinfoilClient.assistantCreate(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.assistantCreate()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.assistantCreate() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("helpful test assistant"), "TinfoilAI.assistantCreate() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.threads() uses EHBP encryption end-to-end
    func testTinfoilAIThreadsUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.threads(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.threads()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.threads() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that TinfoilAI.threadRun() uses EHBP encryption end-to-end
    func testTinfoilAIThreadRunUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.threadRun(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.threadRun()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.threadRun() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("thread run test"), "TinfoilAI.threadRun() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.runs() uses EHBP encryption end-to-end
    func testTinfoilAIRunsUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = RunsQuery(assistantId: "test-assistant-id")

        do {
            _ = try await tinfoilClient.runs(threadId: "test-thread-id", query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.runs()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.runs() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that TinfoilAI.threadsAddMessage() uses EHBP encryption end-to-end
    func testTinfoilAIThreadsAddMessageUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = MessageQuery(role: .user, content: "Secret message for the thread")

        do {
            _ = try await tinfoilClient.threadsAddMessage(threadId: "test-thread-id", query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.threadsAddMessage()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.threadsAddMessage() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Secret message"), "TinfoilAI.threadsAddMessage() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.files() uses EHBP encryption end-to-end
    func testTinfoilAIFilesUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.files(query: query)
        } catch {
            // Expected
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.files()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.files() request MUST have EHBP encapsulated key header")
    }

    // MARK: - Architectural Guarantee Tests

    /// Verifies that TinfoilAI CANNOT be created without an HPKE public key
    /// This ensures EHBP is mandatory - there's no way to bypass it
    func testTinfoilAIRequiresHPKEKey() {
        XCTAssertThrowsError(
            try TinfoilAI(
                apiKey: "test-api-key",
                baseURL: "https://example.com",
                enclaveURL: "https://example.com",
                hpkePublicKeyHex: nil
            ),
            "TinfoilAI should throw when HPKE key is nil"
        ) { error in
            guard let tinfoilError = error as? TinfoilError else {
                XCTFail("Expected TinfoilError, got \(error)")
                return
            }
            if case .invalidConfiguration(let message) = tinfoilError {
                XCTAssertTrue(message.contains("EHBP") || message.contains("HPKE"), "Error should mention EHBP or HPKE")
            } else {
                XCTFail("Expected invalidConfiguration error")
            }
        }
    }

    /// Verifies that TinfoilAI CANNOT be created with an empty HPKE public key
    func testTinfoilAIRejectsEmptyHPKEKey() {
        XCTAssertThrowsError(
            try TinfoilAI(
                apiKey: "test-api-key",
                baseURL: "https://example.com",
                enclaveURL: "https://example.com",
                hpkePublicKeyHex: ""
            ),
            "TinfoilAI should throw when HPKE key is empty"
        ) { error in
            guard let tinfoilError = error as? TinfoilError else {
                XCTFail("Expected TinfoilError, got \(error)")
                return
            }
            if case .invalidConfiguration = tinfoilError {
                // Expected
            } else {
                XCTFail("Expected invalidConfiguration error")
            }
        }
    }

    /// Verifies that ALL TinfoilAI POST requests have non-empty bodies.
    /// This is critical because EHBPClient skips encryption when body is empty:
    /// `if let body = body, !body.isEmpty { ... }`
    /// An empty body would bypass EHBP encryption entirely.
    func testAllPOSTRequestsHaveNonEmptyBodies() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.chats(query: ChatQuery(
                messages: [.user(.init(content: .string("test")))],
                model: "gpt-4"
            ))
        }

        await testStreamingEndpoint("chatsStream", stream: tinfoilClient.chatsStream(query: ChatQuery(
            messages: [.user(.init(content: .string("test")))],
            model: "gpt-4",
            stream: true
        )))

        await testEndpoint("embeddings") {
            _ = try await tinfoilClient.embeddings(query: EmbeddingsQuery(
                input: .string("test"),
                model: "text-embedding-ada-002"
            ))
        }

        await testEndpoint("images") {
            _ = try await tinfoilClient.images(query: ImagesQuery(prompt: "test"))
        }

        await testEndpoint("imageEdits") {
            _ = try await tinfoilClient.imageEdits(query: ImageEditsQuery(
                image: Data("fake".utf8),
                prompt: "test"
            ))
        }

        await testEndpoint("imageVariations") {
            _ = try await tinfoilClient.imageVariations(query: ImageVariationsQuery(
                image: Data("fake".utf8)
            ))
        }

        await testEndpoint("moderations") {
            _ = try await tinfoilClient.moderations(query: ModerationsQuery(input: "test"))
        }

        await testEndpoint("audioCreateSpeech") {
            _ = try await tinfoilClient.audioCreateSpeech(query: AudioSpeechQuery(
                model: .tts_1,
                input: "test",
                voice: .alloy
            ))
        }

        await testStreamingEndpoint("audioCreateSpeechStream", stream: tinfoilClient.audioCreateSpeechStream(query: AudioSpeechQuery(
            model: .tts_1,
            input: "test",
            voice: .alloy
        )))

        await testEndpoint("audioTranscriptions") {
            _ = try await tinfoilClient.audioTranscriptions(query: AudioTranscriptionQuery(
                file: Data("fake".utf8),
                fileType: .mp3,
                model: .whisper_1
            ))
        }

        await testEndpoint("audioTranslations") {
            _ = try await tinfoilClient.audioTranslations(query: AudioTranslationQuery(
                file: Data("fake".utf8),
                fileType: .mp3,
                model: .whisper_1
            ))
        }

        await testEndpoint("assistantCreate") {
            _ = try await tinfoilClient.assistantCreate(query: AssistantsQuery(
                model: "gpt-4",
                name: "test",
                description: nil,
                instructions: nil,
                tools: nil
            ))
        }

        await testEndpoint("assistantModify") {
            _ = try await tinfoilClient.assistantModify(
                query: AssistantsQuery(
                    model: "gpt-4",
                    name: "test",
                    description: nil,
                    instructions: nil,
                    tools: nil
                ),
                assistantId: "asst_123"
            )
        }

        await testEndpoint("threads") {
            _ = try await tinfoilClient.threads(query: ThreadsQuery(messages: []))
        }

        await testEndpoint("threadRun") {
            _ = try await tinfoilClient.threadRun(query: ThreadRunQuery(
                assistantId: "asst_123",
                thread: ThreadsQuery(messages: [])
            ))
        }

        await testEndpoint("runs") {
            _ = try await tinfoilClient.runs(
                threadId: "thread_123",
                query: RunsQuery(assistantId: "asst_123")
            )
        }

        await testEndpoint("runSubmitToolOutputs") {
            _ = try await tinfoilClient.runSubmitToolOutputs(
                threadId: "thread_123",
                runId: "run_456",
                query: RunToolOutputsQuery(toolOutputs: [
                    .init(toolCallId: "call_123", output: "result")
                ])
            )
        }

        await testEndpoint("threadsAddMessage") {
            _ = try await tinfoilClient.threadsAddMessage(
                threadId: "thread_123",
                query: MessageQuery(role: .user, content: "test")
            )
        }

        await testEndpoint("files") {
            _ = try await tinfoilClient.files(query: FilesQuery(
                purpose: "assistants",
                file: Data("test".utf8),
                fileName: "test.txt",
                contentType: "text/plain"
            ))
        }

        await testEndpoint("createResponse") {
            _ = try await tinfoilClient.createResponse(query: CreateModelResponseQuery(
                input: .textInput("test"),
                model: "gpt-4"
            ))
        }

        await testStreamingEndpoint("createResponseStream", stream: tinfoilClient.createResponseStream(query: CreateModelResponseQuery(
            input: .textInput("test"),
            model: "gpt-4",
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

    /// Verifies that TinfoilAI.audioCreateSpeechStream() uses EHBP encryption end-to-end
    func testTinfoilAIAudioCreateSpeechStreamUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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

        let stream = tinfoilClient.audioCreateSpeechStream(query: query)
        for try await _ in stream {
            break
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.audioCreateSpeechStream()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.audioCreateSpeechStream() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Secret streaming speech input"), "TinfoilAI.audioCreateSpeechStream() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.audioTranscriptionsVerbose() uses EHBP encryption end-to-end
    func testTinfoilAIAudioTranscriptionsVerboseUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.audioTranscriptionsVerbose(query: query)
        } catch {
            // Expected - server returns invalid response
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.audioTranscriptionsVerbose()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.audioTranscriptionsVerbose() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that TinfoilAI.audioTranscriptionStream() uses EHBP encryption end-to-end
    func testTinfoilAIAudioTranscriptionStreamUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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

        let stream = tinfoilClient.audioTranscriptionStream(query: query)
        for try await _ in stream {
            break
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.audioTranscriptionStream()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.audioTranscriptionStream() request MUST have EHBP encapsulated key header")
    }

    /// Verifies that TinfoilAI.assistantModify() uses EHBP encryption end-to-end
    func testTinfoilAIAssistantModifyUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: testPublicKey.hexString
        )

        let query = AssistantsQuery(
            model: "gpt-4",
            name: "Modified Assistant",
            description: "Updated description",
            instructions: "Updated secret instructions",
            tools: nil
        )

        do {
            _ = try await tinfoilClient.assistantModify(query: query, assistantId: "asst_123")
        } catch {
            // Expected - server returns invalid response
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.assistantModify()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.assistantModify() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Updated secret instructions"), "TinfoilAI.assistantModify() body MUST be encrypted")
        }
    }

    /// Verifies that TinfoilAI.runSubmitToolOutputs() uses EHBP encryption end-to-end
    func testTinfoilAIRunSubmitToolOutputsUsesEHBPEncryption() async throws {
        let tinfoilClient = try TinfoilAI(
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
            _ = try await tinfoilClient.runSubmitToolOutputs(threadId: "thread_123", runId: "run_456", query: query)
        } catch {
            // Expected - server returns invalid response
        }

        try await Task.sleep(nanoseconds: 100_000_000)

        guard let capturedRequest = server.requestStore.lastRequest else {
            XCTFail("No request was captured from TinfoilAI.runSubmitToolOutputs()")
            return
        }

        let encapsulatedKeyHeader = capturedRequest.headers[EHBPProtocol.encapsulatedKeyHeader]
        XCTAssertNotNil(encapsulatedKeyHeader, "TinfoilAI.runSubmitToolOutputs() request MUST have EHBP encapsulated key header")

        guard let capturedBody = capturedRequest.body else {
            XCTFail("No request body was captured")
            return
        }

        let bodyString = String(data: capturedBody, encoding: .utf8)
        if let bodyString = bodyString {
            XCTAssertFalse(bodyString.contains("Secret tool output result"), "TinfoilAI.runSubmitToolOutputs() body MUST be encrypted")
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

// MARK: - Extensions

extension Character {
    var isHexDigit: Bool {
        return "0123456789abcdefABCDEF".contains(self)
    }
}
