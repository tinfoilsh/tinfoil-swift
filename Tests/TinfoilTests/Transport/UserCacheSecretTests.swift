import XCTest
import Foundation
import CryptoKit
import EHBP
import OpenAI
@testable import Tinfoil

final class UserCacheSecretTests: XCTestCase {

    private func assertIsGeneratedSecret(_ secret: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(secret.count, 64, "expected a hex-encoded 256-bit secret", file: file, line: line)
        XCTAssertEqual(secret, secret.lowercased(), "expected lowercase hex", file: file, line: line)
        XCTAssertTrue(secret.allSatisfy { $0.isHexDigit }, "expected hex digits only", file: file, line: line)
    }

    // MARK: - Resolution

    func testAnExplicitSecretWinsAndOtherwiseTheProcessSecret() {
        XCTAssertEqual(UserCacheSecret.resolve(explicit: "s1"), "s1")
        for unset in [nil, ""] as [String?] {
            let resolved = UserCacheSecret.resolve(explicit: unset)
            assertIsGeneratedSecret(resolved)
            XCTAssertEqual(resolved, UserCacheSecret.processSecret, "Every client in the process shares one secret.")
        }
    }

    /// The SDK reads no environment variable or file for the secret.
    func testTheEnvironmentIsNotRead() {
        setenv("TINFOIL_USER_CACHE_SECRET", "from-the-environment", 1)
        defer { unsetenv("TINFOIL_USER_CACHE_SECRET") }
        XCTAssertEqual(UserCacheSecret.resolve(explicit: nil), UserCacheSecret.processSecret)
    }

    func testGeneratedSecretsAreFresh() {
        let first = UserCacheSecret.generate()
        assertIsGeneratedSecret(first)
        XCTAssertNotEqual(first, UserCacheSecret.generate())
    }

    func testAnEnclaveTheCallerNamesGetsOnlyAnExplicitSecret() throws {
        func connection(secret: String?) throws -> EnclaveConnection {
            try EnclaveHTTPClient.connection(
                enclave: "enclave.example",
                repo: "org/repo",
                transportMode: .tls,
                baseURL: nil,
                attestationRelay: nil,
                userCacheSecret: secret,
                attestor: Attestor(verifier: FakeVerifier(), fetch: { _ in throw TinfoilError.network("no network in this test") }),
                onVerificationResult: nil
            )
        }
        XCTAssertEqual(
            try connection(secret: nil).userCacheSecret,
            "",
            "Only Tinfoil's routers read the secret, so none is resolved for another enclave."
        )
        XCTAssertEqual(try connection(secret: "explicit").userCacheSecret, "explicit")
    }

    func testDiscoveringARouterUsesTheProcessSecret() async throws {
        // A relay skips discovery's network I/O; the route is still Tinfoil's router.
        let connection = try await EnclaveConnection.router(
            attestor: Attestor(verifier: FakeVerifier(), fetch: { _ in throw TinfoilError.network("no network in this test") }),
            transportMode: .ehbp,
            baseURL: nil,
            attestationRelay: "relay.example",
            userCacheSecret: nil,
            onVerificationResult: nil
        )
        XCTAssertEqual(connection.userCacheSecret, UserCacheSecret.processSecret)
    }

    // MARK: - Injection

    private func postRequest(path: String, body: String?) -> URLRequest {
        var request = URLRequest(url: URL(string: "https://enclave.example.com\(path)")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let body {
            request.httpBody = Data(body.utf8)
        }
        return request
    }

    func testInjectsOnEligiblePaths() throws {
        let paths = [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/responses",
            "/api/v1/chat/completions", // proxy base URL with a path prefix
            "/chat/completions", // custom base URL without a /v1 root
        ]
        for path in paths {
            let raw = #"{"model":"m"}"#
            let request = postRequest(path: path, body: raw)
            var headers = ["Content-Type": "application/json", "Content-Length": String(raw.utf8.count)]

            let body = try XCTUnwrap(
                UserCacheSecret.provision(request: request, headers: &headers, clientSecret: "s1"),
                "expected a body for \(path)"
            )
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
            XCTAssertEqual(object["model"] as? String, "m")
            XCTAssertEqual(object[UserCacheSecret.bodyField] as? String, "s1", "expected injection on \(path)")

            // Length metadata must describe the injected bytes: the sealing
            // client frames and encrypts exactly what we hand it, so a stale
            // Content-Length would describe a body that no longer exists.
            XCTAssertEqual(headers["Content-Length"], String(body.count))
        }
    }

    func testSkipsIneligibleRequests() throws {
        // Non-allowlisted endpoints forward the body byte-identical.
        let raw = #"{"model":"m","input":"text"}"#
        var headers: [String: String] = [:]
        for path in ["/v1/embeddings", "/embeddings"] {
            let embeddings = postRequest(path: path, body: raw)
            XCTAssertEqual(
                UserCacheSecret.provision(request: embeddings, headers: &headers, clientSecret: "s1"),
                Data(raw.utf8),
                "expected no injection on \(path)"
            )
        }

        // GET with no body is forwarded as-is.
        var get = URLRequest(url: URL(string: "https://enclave.example.com/v1/models")!)
        get.httpMethod = "GET"
        XCTAssertNil(UserCacheSecret.provision(request: get, headers: &headers, clientSecret: "s1"))

        // An empty client-level secret disables injection.
        let chat = postRequest(path: "/v1/chat/completions", body: #"{"model":"m"}"#)
        XCTAssertEqual(
            UserCacheSecret.provision(request: chat, headers: &headers, clientSecret: ""),
            Data(#"{"model":"m"}"#.utf8)
        )
    }

    func testNeverClobbersNonEmptyExistingField() {
        let bodies = [
            #"{"model":"m","user_cache_secret":"end-user-7"}"#,        // explicit per-request secret
            #"{"model":"m","user_cache_secre\u0074":"end-user-7"}"#, // escaped spelling of the same key
        ]
        for raw in bodies {
            let request = postRequest(path: "/v1/chat/completions", body: raw)
            var headers: [String: String] = [:]
            XCTAssertEqual(
                UserCacheSecret.provision(request: request, headers: &headers, clientSecret: "client-level"),
                Data(raw.utf8),
                "a body that already carries the field must pass through byte-identical"
            )
        }
    }

    func testReplacesEmptyExistingField() throws {
        let cases = [
            (
                #"{"large":9007199254740993,"user_cache_secret":"","nested":{"value":1}}  "#,
                #"{"large":9007199254740993,"user_cache_secret":"client-level","nested":{"value":1}}  "#
            ),
            (
                #"{"user_cache_secre\u0074":""}"#,
                #"{"user_cache_secre\u0074":"client-level"}"#
            ),
        ]
        for (raw, expected) in cases {
            let request = postRequest(path: "/v1/chat/completions", body: raw)
            var headers = ["Content-Length": String(raw.utf8.count)]
            let body = try XCTUnwrap(
                UserCacheSecret.provision(request: request, headers: &headers, clientSecret: "client-level")
            )

            XCTAssertEqual(String(decoding: body, as: UTF8.self), expected)
            XCTAssertEqual(headers["Content-Length"], String(body.count))
        }
    }

    func testDuplicateDecodedExistingFieldsForwardedUntouched() {
        let keys = [
            #""user_cache_secret""#,
            #""user_cache_secre\u0074""#,
        ]
        let values = [
            #""""#,
            #""per-request""#,
        ]

        for firstKey in keys {
            for secondKey in keys {
                for firstValue in values {
                    for secondValue in values {
                        let raw = """
                        {"large":9007199254740993,\(firstKey):\(firstValue),\(secondKey):\(secondValue)}
                        """
                        let request = postRequest(path: "/v1/chat/completions", body: raw)
                        var headers = ["Content-Length": String(raw.utf8.count)]

                        XCTAssertEqual(
                            UserCacheSecret.provision(
                                request: request,
                                headers: &headers,
                                clientSecret: "client-level"
                            ),
                            Data(raw.utf8),
                            "duplicate decoded fields must not trigger an ambiguous rewrite: \(raw)"
                        )
                        XCTAssertEqual(headers["Content-Length"], String(raw.utf8.count))
                    }
                }
            }
        }
    }

    func testNonObjectBodiesForwardedUntouched() {
        // The trailing '}' / ']' cases matter: a parser that stops at the
        // first complete object would re-serialize the body with the trailing
        // bytes silently dropped, turning a request the server rejects into
        // one it accepts.
        let bodies = [
            "not json",
            "[1,2,3]",
            "null",
            #"{"model":"m"} trailing"#,
            #"{"model":"m"}}"#,
            #"{"model":"m"}]"#,
            #"{"model":"m"}} garbage"#,
            // Malformed variants the structural scan must reject too.
            "{",
            #"{"a":}"#,
            #"{"a":1,}"#,
            #"{"a" "b"}"#,
            #"{"a":01}"#,
            #"{"a":truey}"#,
            #"{"a":"unterminated"#,
        ]
        for raw in bodies {
            let request = postRequest(path: "/v1/chat/completions", body: raw)
            var headers: [String: String] = [:]
            XCTAssertEqual(
                UserCacheSecret.provision(request: request, headers: &headers, clientSecret: "s1"),
                Data(raw.utf8),
                "bodies the router-side schema would reject must be forwarded untouched: \(raw)"
            )
        }
    }

    func testInvalidUTF8BodyForwardedUntouched() {
        let raw = Data([0x7B, 0x22, 0x78, 0x22, 0x3A, 0x22, 0xFF, 0x22, 0x7D])
        var request = URLRequest(url: URL(string: "https://enclave.example.com/v1/chat/completions")!)
        request.httpMethod = "POST"
        request.httpBody = raw
        var headers: [String: String] = [:]

        XCTAssertEqual(
            UserCacheSecret.provision(request: request, headers: &headers, clientSecret: "s1"),
            raw
        )
    }

    func testAllowsTrailingWhitespace() throws {
        // Trailing whitespace is not trailing data: strict JSON parsers
        // accept it, so the injection must too — clients routinely end
        // bodies with \n.
        let request = postRequest(path: "/v1/chat/completions", body: "{\"model\":\"m\"}\n\t ")
        var headers: [String: String] = [:]
        let body = try XCTUnwrap(UserCacheSecret.provision(request: request, headers: &headers, clientSecret: "s1"))

        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(object[UserCacheSecret.bodyField] as? String, "s1")
        XCTAssertTrue(
            String(decoding: body, as: UTF8.self).hasSuffix("}\n\t "),
            "the caller's whitespace framing must be preserved"
        )
    }

    func testPreservesNumberPrecision() throws {
        // 2^53+1 is not representable as a Double; a decode/re-encode cycle
        // that goes through floating point would corrupt it.
        let request = postRequest(path: "/v1/chat/completions", body: #"{"model":"m","seed":9007199254740993}"#)
        var headers: [String: String] = [:]
        let body = try XCTUnwrap(UserCacheSecret.provision(request: request, headers: &headers, clientSecret: "s1"))

        let text = String(decoding: body, as: UTF8.self)
        XCTAssertTrue(text.contains(#""seed":9007199254740993"#), "seed must survive injection intact: \(text)")
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(object[UserCacheSecret.bodyField] as? String, "s1")
    }

    func testEscapesSecretWhenSplicing() throws {
        // A caller-supplied secret is spliced into JSON source text, so any
        // JSON-significant characters in it must be escaped.
        let hostile = #"s1"},"x":"\"#
        let injected = try XCTUnwrap(UserCacheSecret.inject(into: Data(#"{"model":"m"}"#.utf8), secret: hostile))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: injected) as? [String: Any])
        XCTAssertEqual(object[UserCacheSecret.bodyField] as? String, hostile)
        XCTAssertEqual(object.count, 2)
    }

    func testInjectsIntoEmptyObject() throws {
        let injected = try XCTUnwrap(UserCacheSecret.inject(into: Data("{}".utf8), secret: "s1"))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: injected) as? [String: Any])
        XCTAssertEqual(object[UserCacheSecret.bodyField] as? String, "s1")
        XCTAssertEqual(object.count, 1)
    }

    func testUnsupportedJSONForwardedUntouched() {
        let depth = 600
        let bodies = [
            #"{"model":"m","x":1e999}"#,
            #"{"model":"m","a":"#
                + String(repeating: #"{"n":"#, count: depth)
                + "1"
                + String(repeating: "}", count: depth)
                + "}",
        ]
        for raw in bodies {
            let request = postRequest(path: "/v1/chat/completions", body: raw)
            var headers: [String: String] = [:]
            XCTAssertEqual(
                UserCacheSecret.provision(request: request, headers: &headers, clientSecret: "s1"),
                Data(raw.utf8)
            )
        }
    }

    func testBracesInsideStringsDoNotConfuseInjection() throws {
        let raw = #"{"a":"} \" { not the end","b":[1,2]}"#
        let injected = try XCTUnwrap(UserCacheSecret.inject(into: Data(raw.utf8), secret: "s1"))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: injected) as? [String: Any])
        XCTAssertEqual(object["a"] as? String, #"} " { not the end"#)
        XCTAssertEqual(object[UserCacheSecret.bodyField] as? String, "s1")
        XCTAssertEqual(object.count, 3)
    }

    // MARK: - End to end through the real client machinery

    /// Drives the real Client client (OpenAI SDK -> EHBP session) against
    /// a local server holding the matching HPKE private key, pinning that the
    /// client-level secret rides inside the sealed body exactly as the SDK
    /// builds it — and that a per-request field set via `ChatQuery.extraBody`
    /// wins over the client-level secret.
    func testEndToEndThroughTinfoilClient() async throws {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let server = LocalTestServer()
        server.responseBody = {
            // A zero-length chunk: enough for EHBP response framing; the
            // OpenAI decode then fails, which the test tolerates.
            var data = Data()
            var length = UInt32(0).bigEndian
            data.append(Data(bytes: &length, count: 4))
            return data
        }()
        try server.start()
        defer { server.stop() }

        let client = try Client(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: privateKey.publicKey.rawRepresentation.hexString,
            userCacheSecret: "client-level"
        )

        // The client-level secret arrives inside the encrypted body.
        let query = ChatQuery(
            messages: [.user(.init(content: .string("hi")))],
            model: "m"
        )
        do { _ = try await client.chats(query: query) } catch {
            // Expected: the mock response is not a valid chat completion.
        }
        try await Task.sleep(nanoseconds: 100_000_000)

        var body = try decryptedRequestBody(from: server, privateKey: privateKey)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(server.requestStore.lastRequest?.path, "/v1/chat/completions")
        XCTAssertEqual(object[UserCacheSecret.bodyField] as? String, "client-level")
        XCTAssertEqual(object["model"] as? String, "m")

        // The streaming session seals the same injected body.
        server.requestStore.clear()
        let streamQuery = ChatQuery(
            messages: [.user(.init(content: .string("hi")))],
            model: "m",
            stream: true
        )
        do {
            for try await _ in client.chatsStream(query: streamQuery) {}
        } catch {
            // Expected: the mock response carries no usable chunks.
        }
        try await Task.sleep(nanoseconds: 100_000_000)

        body = try decryptedRequestBody(from: server, privateKey: privateKey)
        object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(object[UserCacheSecret.bodyField] as? String, "client-level")

        // A per-request field set through the public API wins over the
        // client-level secret.
        server.requestStore.clear()
        let overrideQuery = ChatQuery(
            messages: [.user(.init(content: .string("hi")))],
            model: "m",
            extraBody: [UserCacheSecret.bodyField: .string("end-user-7")]
        )
        do { _ = try await client.chats(query: overrideQuery) } catch {
            // Expected: the mock response is not a valid chat completion.
        }
        try await Task.sleep(nanoseconds: 100_000_000)

        body = try decryptedRequestBody(from: server, privateKey: privateKey)
        object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(
            object[UserCacheSecret.bodyField] as? String,
            "end-user-7",
            "a per-request field must win over the client-level secret"
        )
    }

    /// Decrypts the last captured EHBP request body with the server's HPKE
    /// private key, proving the injected field sits inside the sealed body.
    private func decryptedRequestBody(
        from server: LocalTestServer,
        privateKey: Curve25519.KeyAgreement.PrivateKey
    ) throws -> Data {
        let request = try XCTUnwrap(server.requestStore.lastRequest, "no request was captured")
        let encapsulatedHex = try XCTUnwrap(
            request.headers[EHBPProtocol.encapsulatedKeyHeader],
            "request must carry the EHBP encapsulated key"
        )
        let encapsulatedKey = try XCTUnwrap(Data(hexString: encapsulatedHex))
        let framed = [UInt8](try XCTUnwrap(request.body, "no request body was captured"))

        // Request framing: LEN (4 bytes big-endian) || ciphertext.
        XCTAssertGreaterThan(framed.count, 4)
        let length = Int(framed[0]) << 24 | Int(framed[1]) << 16 | Int(framed[2]) << 8 | Int(framed[3])
        XCTAssertEqual(framed.count, 4 + length, "body must be a single framed chunk")
        let ciphertext = Data(framed[4...])

        var recipient = try HPKE.Recipient(
            privateKey: privateKey,
            ciphersuite: HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256),
            info: Data(EHBPConstants.hpkeRequestInfo.utf8),
            encapsulatedKey: encapsulatedKey
        )
        return try recipient.open(ciphertext)
    }
}
