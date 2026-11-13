import XCTest
import Foundation
@testable import Tinfoil

/// How the gateway client prepares a request. The salts and cache prefixes
/// are the ones tinfoil-go derives for the same bodies, secret and API key,
/// so that every SDK scopes the prompt cache alike.
final class GatewayRequestTests: XCTestCase {
    private func request(
        _ body: String,
        path: String = "/v1/chat/completions",
        contentType: String = "application/json",
        authorization: String = "Bearer test-key"
    ) -> URLRequest {
        var request = URLRequest(url: URL(string: "https://gw.example\(path)")!)
        request.httpMethod = "POST"
        request.httpBody = Data(body.utf8)
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        request.setValue(authorization, forHTTPHeaderField: "Authorization")
        return request
    }

    private func members(_ request: URLRequest) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: Any])
    }

    private func assertConfigurationError(
        _ body: () throws -> Any,
        _ message: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            guard case TinfoilError.configurationError(let failure) = error else {
                return XCTFail("expected a configuration error, got \(error)", file: file, line: line)
            }
            XCTAssertEqual(failure.message, message, file: file, line: line)
        }
    }

    // Vectors from tinfoil-go's internal/gateway, for the client secret
    // "client-secret" and the API key "test-key".
    private static let clientSecretSalt = "9y3eKe8di08vn_xH9QkBgKKe1d1dS69UmzThhrWwVGs"

    func testTheSaltAndPrefixMatchGo() throws {
        let body = #"{"model":"m","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"hi"}],"n":12345678901234567890}"#
        let prepared = try GatewayRequest.prepare(request(body), secret: "client-secret")

        XCTAssertEqual(prepared.value(forHTTPHeaderField: GatewayRequest.modelHeader), "m")
        XCTAssertEqual(
            prepared.value(forHTTPHeaderField: GatewayRequest.cachePrefixHeader),
            "9cacd28b5f2325189df9064e69f080dd799d51d6fb7ca31814f8cb50a273db5a"
        )
        let sent = String(decoding: try XCTUnwrap(prepared.httpBody), as: UTF8.self)
        XCTAssertEqual(
            sent,
            #"{"model":"m","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"hi"}],"n":12345678901234567890,"cache_salt":"\#(Self.clientSecretSalt)"}"#,
            "Every member keeps the caller's bytes, a number beyond 2^53 included."
        )
    }

    func testABodySecretReplacesTheClientsAndNeverLeaves() throws {
        let body = #"{"model":"m","instructions":"follow these","input":"x","user_cache_secret":"body-secret"}"#
        let prepared = try GatewayRequest.prepare(request(body), secret: "client-secret")

        XCTAssertEqual(
            prepared.value(forHTTPHeaderField: GatewayRequest.cachePrefixHeader),
            "ecb05d5ed656ed9074539d7b7bc91e2d5c8d6d5eba12d1aa14b8c4c73f56ae87",
            "The instructions are the prompt's head."
        )
        let json = try members(prepared)
        XCTAssertEqual(json["cache_salt"] as? String, "CA8UcB4Ah2nVIoIQtBSU5vvaIoybPy9symLz3b7L0vY")
        XCTAssertNil(json["user_cache_secret"])
        XCTAssertFalse(String(decoding: try XCTUnwrap(prepared.httpBody), as: UTF8.self).contains("body-secret"))
    }

    func testACallersSaltIsReplacedAndAStringPromptIsItsOwnHead() throws {
        let body = #"{"model":"m","prompt":"just a string","cache_salt":"old"}"#
        let prepared = try GatewayRequest.prepare(request(body), secret: "client-secret")

        XCTAssertEqual(
            prepared.value(forHTTPHeaderField: GatewayRequest.cachePrefixHeader),
            "972f42589a2e262c18b8a609158524ec500821904ee19aac2a1638c2103e0d51"
        )
        XCTAssertEqual(
            String(decoding: try XCTUnwrap(prepared.httpBody), as: UTF8.self),
            #"{"model":"m","prompt":"just a string","cache_salt":"\#(Self.clientSecretSalt)"}"#
        )
    }

    func testAnEmptyConversationHasNoPrefix() throws {
        var original = request(#"{"model":"m","messages":[]}"#)
        original.setValue("caller-prefix", forHTTPHeaderField: GatewayRequest.cachePrefixHeader)
        let prepared = try GatewayRequest.prepare(original, secret: "client-secret")
        XCTAssertNil(prepared.value(forHTTPHeaderField: GatewayRequest.cachePrefixHeader), "A caller's prefix is dropped with a secret.")
        XCTAssertEqual(try members(prepared)["cache_salt"] as? String, Self.clientSecretSalt)
    }

    func testWithoutASecretTheBodyIsUnchanged() throws {
        let body = #"{"model":"m", "messages":[{"role":"user","content":"hi"}]}"#
        var original = request(body)
        original.setValue("caller-prefix", forHTTPHeaderField: GatewayRequest.cachePrefixHeader)
        let prepared = try GatewayRequest.prepare(original, secret: "")
        XCTAssertEqual(prepared.httpBody, Data(body.utf8))
        XCTAssertEqual(prepared.value(forHTTPHeaderField: GatewayRequest.cachePrefixHeader), "caller-prefix")
        XCTAssertEqual(prepared.value(forHTTPHeaderField: GatewayRequest.modelHeader), "m")
    }

    func testAnEndpointWithoutAPromptCacheIsNotScoped() throws {
        let body = #"{"model":"e","input":"x","user_cache_secret":"s"}"#
        let prepared = try GatewayRequest.prepare(request(body, path: "/v1/embeddings"), secret: "client-secret")
        XCTAssertEqual(prepared.httpBody, Data(body.utf8))
        XCTAssertEqual(prepared.value(forHTTPHeaderField: GatewayRequest.modelHeader), "e")
    }

    func testTheCallersModelHeaderIsKept() throws {
        var original = request(#"{"model":"body-model"}"#)
        original.setValue("header-model", forHTTPHeaderField: GatewayRequest.modelHeader)
        let prepared = try GatewayRequest.prepare(original, secret: "")
        XCTAssertEqual(prepared.value(forHTTPHeaderField: GatewayRequest.modelHeader), "header-model")
    }

    func testRepeatedMembersAreRefused() {
        assertConfigurationError({ try GatewayRequest.prepare(self.request(#"{"model":"a","model":"b"}"#), secret: "") },
                                 #"request body repeats the "model" member"#)
        assertConfigurationError(
            { try GatewayRequest.prepare(self.request(#"{"model":"a","user_cache_secret":"x","cache_salt":"y","user_cache_secret":"z","cache_salt":"w"}"#), secret: "") },
            #"request body repeats the "user_cache_secret", "cache_salt" members"#
        )
    }

    func testOtherBodiesPassThrough() throws {
        for (body, contentType) in [
            (#"[{"model":"m"}]"#, "application/json"),
            (#"{"model":"m",}"#, "application/json"),
            (#"{"model":"m"} {}"#, "application/json"),
            (#"{"model":"m"}"#, "text/plain"),
        ] {
            let original = request(body, contentType: contentType)
            let prepared = try GatewayRequest.prepare(original, secret: "client-secret")
            XCTAssertEqual(prepared, original, body)
        }
        var get = request("")
        get.httpMethod = "GET"
        get.httpBody = nil
        XCTAssertEqual(try GatewayRequest.prepare(get, secret: "client-secret"), get)
    }

    func testAStreamedBodyIsRefused() {
        var original = request("")
        original.httpBody = nil
        original.httpBodyStream = InputStream(data: Data(#"{"model":"m"}"#.utf8))
        assertConfigurationError({ try GatewayRequest.prepare(original, secret: "") },
                                 "the gateway client needs a request's body as httpBody, not a stream")
    }

    func testBearerCredential() {
        XCTAssertEqual(GatewayRequest.bearerCredential("Bearer key"), "key")
        XCTAssertEqual(GatewayRequest.bearerCredential("  bearer   key  "), "key")
        XCTAssertEqual(GatewayRequest.bearerCredential("Basic key"), "")
        XCTAssertEqual(GatewayRequest.bearerCredential("Bearer"), "")
    }

    // MARK: - Multipart

    private func multipart(_ fields: [(disposition: String, value: String)], boundary: String = "XyZ") -> URLRequest {
        var body = "preamble\r\n"
        for field in fields {
            body += "--\(boundary)\r\nContent-Disposition: \(field.disposition)\r\n\r\n\(field.value)\r\n"
        }
        body += "--\(boundary)--\r\n"
        return request(body, path: "/v1/audio/transcriptions", contentType: "multipart/form-data; boundary=\(boundary)")
    }

    func testAMultipartUploadNamesItsModel() throws {
        let original = multipart([
            ("form-data; name=\"file\"; filename=\"a.wav\"", "RIFF"),
            ("form-data; name=\"model\"", "whisper"),
        ])
        let prepared = try GatewayRequest.prepare(original, secret: "client-secret")
        XCTAssertEqual(prepared.value(forHTTPHeaderField: GatewayRequest.modelHeader), "whisper")
        XCTAssertEqual(prepared.httpBody, original.httpBody, "An upload is sent as it is.")
    }

    func testAMultipartUploadNeedsExactlyOneModelField() {
        let message = "multipart upload must contain exactly one non-empty model field"
        for fields in [
            [(disposition: "form-data; name=\"file\"", value: "x")],
            [("form-data; name=\"model\"", "a"), ("form-data; name=\"model\"", "b")],
            [("form-data; name=\"model\"", "  ")],
            [("form-data; name=\"model\"; filename=\"m\"", "a")],
        ] {
            assertConfigurationError({ try GatewayRequest.prepare(self.multipart(fields), secret: "") }, message)
        }
        assertConfigurationError(
            { try GatewayRequest.prepare(self.request("--x\r\n", contentType: "multipart/form-data"), secret: "") },
            "multipart upload is missing its boundary"
        )
        assertConfigurationError(
            { try GatewayRequest.prepare(self.request("no parts", contentType: "multipart/form-data; boundary=q"), secret: "") },
            "invalid multipart upload"
        )
    }

    func testAnExplicitModelHeaderSkipsParsingAnUpload() throws {
        var original = request("not multipart at all", contentType: "multipart/form-data; boundary=q")
        original.setValue("m", forHTTPHeaderField: GatewayRequest.modelHeader)
        XCTAssertEqual(try GatewayRequest.prepare(original, secret: ""), original)
    }
}
