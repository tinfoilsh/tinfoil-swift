import XCTest
import CryptoKit
import EHBP
@testable import TinfoilAI

final class SpeechTests: XCTestCase {
    private static let pcmContentType = "audio/pcm"
    private static let audioChunks = [Data([0x00]), Data([0x80, 0xff, 0x7f])]

    func testStreamsEncryptedPCMAndPreservesProviderRequest() async throws {
        let fixture = try EncryptedSpeechFixture(chunks: { _ in Self.audioChunks })
        defer { fixture.server.stop() }
        let client = try fixture.makeClient()
        let query = Self.query(input: "Read this private response aloud.")

        let chunks = try await collect(client.audioCreateSpeechStream(
            query: query,
            options: .init(expectedContentType: Self.pcmContentType)
        ))
        XCTAssertEqual(chunks, Self.audioChunks)

        let wire = try XCTUnwrap(fixture.server.requestStore.lastRequest)
        let clear = try XCTUnwrap(fixture.decryptedRequests.lastRequest)
        let body = try XCTUnwrap(clear.body)
        let decoded = try JSONDecoder().decode(AudioSpeechQuery.self, from: body)
        XCTAssertEqual(wire.method, "POST")
        XCTAssertEqual(wire.path, "/v1/audio/speech")
        XCTAssertEqual(wire.headers["Authorization"], "Bearer test-speech-key")
        XCTAssertEqual(wire.headers["X-Tinfoil-Enclave-Url"], EncryptedSpeechFixture.enclaveURL)
        XCTAssertNotNil(wire.headers[EHBPProtocol.encapsulatedKeyHeader])
        XCTAssertNotEqual(wire.body, body)
        XCTAssertFalse(String(data: wire.body ?? Data(), encoding: .utf8)?.contains(query.input) ?? false)
        XCTAssertEqual(decoded.model, query.model)
        XCTAssertEqual(decoded.input, query.input)
        XCTAssertEqual(decoded.voice, query.voice)
        XCTAssertEqual(decoded.instructions, query.instructions)
        XCTAssertEqual(decoded.speed, query.speed)
        XCTAssertEqual(decoded.responseFormat, .pcm)
        XCTAssertEqual(decoded.streamFormat, .audio)
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertNil(fields["expectedContentType"])
    }

    func testExistingStreamingAndBufferedSpeechMethodsStillDecryptAudio() async throws {
        let fixture = try EncryptedSpeechFixture(contentType: "audio/mpeg", chunks: { _ in Self.audioChunks })
        defer { fixture.server.stop() }
        let client = try fixture.makeClient()
        let query = AudioSpeechQuery(model: .tts_1, input: "Hello", voice: .alloy)

        let streamed = try await collect(client.audioCreateSpeechStream(query: query))
        XCTAssertEqual(streamed, Self.audioChunks)
        let buffered = try await client.audioCreateSpeech(query: query)
        XCTAssertEqual(buffered.audio, Self.audioChunks.reduce(into: Data()) { $0.append($1) })
        XCTAssertEqual(fixture.decryptedRequests.requests.count, 2)
    }

    func testSpeechOptionsRejectUnexpectedContentTypesOverEHBP() async throws {
        for contentType in ["audio/wav", "application/json"] {
            let fixture = try EncryptedSpeechFixture(contentType: contentType, chunks: { _ in Self.audioChunks })
            defer { fixture.server.stop() }
            let client = try fixture.makeClient()
            do {
                for try await _ in client.audioCreateSpeechStream(
                    query: Self.query(), options: .init(expectedContentType: Self.pcmContentType)
                ) {
                    XCTFail("An incompatible response must not be delivered as audio")
                }
                XCTFail("Expected content-type validation to fail")
            } catch {
                XCTAssertEqual(error as? AudioSpeechStreamError, .unexpectedContentType(contentType))
            }
            XCTAssertEqual(fixture.decryptedRequests.requests.count, 1)
        }
    }

    func testEncryptedAPIErrorIsDecodedWithoutYieldingAudio() async throws {
        let errorBody = Data("""
            {"error":{"message":"Speech limit reached","type":"rate_limit_error","code":"speech_limit"}}
            """.utf8)
        let split = errorBody.count / 2
        let fixture = try EncryptedSpeechFixture(statusCode: 429, contentType: "application/json", chunks: { _ in
            [Data(errorBody.prefix(split)), Data(errorBody.dropFirst(split))]
        })
        defer { fixture.server.stop() }
        let client = try fixture.makeClient()
        do {
            for try await _ in client.audioCreateSpeechStream(query: Self.query(), options: .init(expectedContentType: Self.pcmContentType)) {
                XCTFail("API errors must not be delivered as audio")
            }
            XCTFail("Expected the API error")
        } catch {
            let apiError = try XCTUnwrap(error as? APIErrorResponse)
            XCTAssertEqual(apiError.error.code, "speech_limit")
            XCTAssertEqual(apiError.error.message, "Speech limit reached")
        }
        XCTAssertEqual(fixture.server.requestStore.requests.count, 1)
    }

    func testTamperedAudioIsRejectedBeforeDelivery() async throws {
        let fixture = try EncryptedSpeechFixture(tamperResponse: true, chunks: { _ in [Data([0x01, 0x02])] })
        defer { fixture.server.stop() }
        let client = try fixture.makeClient()
        do {
            for try await _ in client.audioCreateSpeechStream(query: Self.query()) {
                XCTFail("Unauthenticated audio must not be delivered")
            }
            XCTFail("Expected authentication failure")
        } catch {
            guard case CryptoKitError.authenticationFailure = error else {
                return XCTFail("Expected authentication failure, got \(error)")
            }
        }
        XCTAssertEqual(fixture.server.requestStore.requests.count, 1)
    }

    func testSuccessfulPlaintextResponseDoesNotBypassEncryption() async throws {
        let fixture = try EncryptedSpeechFixture(encryptResponse: false, chunks: { _ in Self.audioChunks })
        defer { fixture.server.stop() }
        let client = try fixture.makeClient()
        do {
            for try await _ in client.audioCreateSpeechStream(query: Self.query()) {
                XCTFail("Plaintext success responses must not be delivered")
            }
            XCTFail("Expected a missing encryption header error")
        } catch {
            guard case EHBPError.missingHeader(let name) = error else {
                return XCTFail("Expected a missing header error, got \(error)")
            }
            XCTAssertEqual(name, EHBPProtocol.responseNonceHeader)
        }
    }

    func testConcurrentSpeechStreamsKeepResponsesAndKeysSeparate() async throws {
        let fixture = try EncryptedSpeechFixture(chunks: { [Data($0.input.utf8)] })
        defer { fixture.server.stop() }
        let client = try fixture.makeClient()
        let first = Self.query(input: "First response")
        let second = Self.query(input: "Second response")
        async let firstAudio = collect(client.audioCreateSpeechStream(query: first, options: .init(expectedContentType: Self.pcmContentType)))
        async let secondAudio = collect(client.audioCreateSpeechStream(query: second, options: .init(expectedContentType: Self.pcmContentType)))
        let results = try await (firstAudio, secondAudio)
        XCTAssertEqual(results.0, [Data(first.input.utf8)])
        XCTAssertEqual(results.1, [Data(second.input.utf8)])
        let keys = fixture.server.requestStore.requests.compactMap { $0.headers[EHBPProtocol.encapsulatedKeyHeader] }
        XCTAssertEqual(Set(keys).count, 2)
    }

    private static func query(input: String = "Read aloud") -> AudioSpeechQuery {
        AudioSpeechQuery(
            model: "qwen3-tts", input: input, voice: .custom("aiden"),
            instructions: "Speak clearly.", responseFormat: .pcm, streamFormat: .audio
        )
    }

    private func collect(_ stream: AsyncThrowingStream<AudioSpeechResult, Error>) async throws -> [Data] {
        var chunks: [Data] = []
        for try await result in stream { chunks.append(result.audio) }
        return chunks
    }
}

private final class EncryptedSpeechFixture {
    static let enclaveURL = "https://verified-speech.example"
    let server = LocalTestServer()
    let decryptedRequests = HTTPRequestStore()
    private let privateKey = Curve25519.KeyAgreement.PrivateKey()

    init(
        statusCode: Int = 200,
        contentType: String = "audio/pcm",
        encryptResponse: Bool = true,
        tamperResponse: Bool = false,
        chunks: @escaping (AudioSpeechQuery) -> [Data]
    ) throws {
        let nonce = try XCTUnwrap(Data(hexString: server.responseNonce))
        server.responseHandler = { [privateKey, decryptedRequests] request in
            do {
                let encapsulatedKey = try XCTUnwrap(request.headers[EHBPProtocol.encapsulatedKeyHeader].flatMap(Data.init(hexString:)))
                let body = try XCTUnwrap(request.body)
                let prefixBytes = EHBPConstants.responseLengthPrefixBytes
                let length = body.prefix(prefixBytes).reduce(0) { ($0 << UInt8.bitWidth) | Int($1) }
                XCTAssertEqual(body.count, prefixBytes + length)
                var recipient = try HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: .init(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256),
                    info: Data(EHBPConstants.hpkeRequestInfo.utf8),
                    encapsulatedKey: encapsulatedKey
                )
                let plaintext = try recipient.open(body.dropFirst(prefixBytes))
                decryptedRequests.append(.init(method: request.method, path: request.path, headers: request.headers, body: plaintext))
                let query = try JSONDecoder().decode(AudioSpeechQuery.self, from: plaintext)
                let plaintextChunks = chunks(query)
                var responseBody = Data()
                if encryptResponse {
                    let secret = try recipient.exportSecret(
                        context: Data(EHBPConstants.exportLabel.utf8), outputByteCount: EHBPConstants.exportLength
                    )
                    let material = try deriveResponseKeys(
                        exportedSecret: secret.withUnsafeBytes { Data($0) },
                        requestEnc: encapsulatedKey, responseNonce: nonce
                    )
                    for (sequence, plaintext) in plaintextChunks.enumerated() {
                        let ciphertext = try encryptChunk(keyMaterial: material, seq: UInt64(sequence), plaintext: plaintext)
                        var length = UInt32(ciphertext.count).bigEndian
                        responseBody.append(Data(bytes: &length, count: prefixBytes))
                        responseBody.append(ciphertext)
                    }
                } else {
                    plaintextChunks.forEach { responseBody.append($0) }
                }
                if tamperResponse, !responseBody.isEmpty {
                    responseBody[responseBody.index(before: responseBody.endIndex)] ^= 1
                }
                return .init(statusCode: statusCode, contentType: contentType, body: responseBody, includeNonce: encryptResponse)
            } catch {
                XCTFail("Failed to construct the encrypted speech fixture: \(error)")
                return .init(statusCode: 500, contentType: "text/plain", body: Data(), includeNonce: false)
            }
        }
        try server.start()
    }

    func makeClient() throws -> TinfoilAI {
        try TinfoilAI(
            apiKey: "test-speech-key", baseURL: server.baseURL, enclaveURL: Self.enclaveURL,
            hpkePublicKeyHex: privateKey.publicKey.rawRepresentation.hexString,
            userCacheSecret: "test-speech-cache-secret"
        )
    }
}
