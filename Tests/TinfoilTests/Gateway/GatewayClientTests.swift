import XCTest
import Foundation
import OpenAI
@testable import Tinfoil

/// The public gateway clients: the configuration checks that come before any
/// network I/O, and live runs against Tinfoil's gateway.
final class GatewayClientTests: XCTestCase {
    private func assertRefusedBeforeIO(
        _ expected: String,
        modelPins: [String: ModelPin] = [:],
        pinnedModelsOnly: Bool = false,
        baseURL: URL? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await GatewayHTTPClient(
                modelPins: modelPins,
                pinnedModelsOnly: pinnedModelsOnly,
                baseURL: baseURL,
                userCacheSecret: "test-secret",
                catalog: {
                    XCTFail("the catalog was read despite a refused configuration", file: file, line: line)
                    return [:]
                }
            )
            XCTFail("expected \(expected)", file: file, line: line)
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains(expected), "\(failure.message) should mention \(expected)", file: file, line: line)
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
        }
    }

    func testTheConfigurationIsCheckedBeforeAnyNetworkIO() async {
        await assertRefusedBeforeIO("the gateway base URL must use HTTPS", baseURL: URL(string: "http://localhost/v1/")!)
        await assertRefusedBeforeIO("must not carry a query or a fragment", baseURL: URL(string: "https://gw.example/v1/?")!)
        await assertRefusedBeforeIO("must not carry a query or a fragment", baseURL: URL(string: "https://gw.example/v1/#x")!)
        await assertRefusedBeforeIO("carry no credentials", baseURL: URL(string: "https://user:pass@gw.example/v1/")!)
        await assertRefusedBeforeIO("pinned-only mode requires at least one model pin", pinnedModelsOnly: true)
        await assertRefusedBeforeIO("must belong to tinfoilsh/", modelPins: ["m": ModelPin(repo: "someone/model")])
        await assertRefusedBeforeIO(#"model "m""#, modelPins: ["m": ModelPin(repo: "tinfoilsh/")])
    }

    func testTheRelayKeepsThePortAndBracketsAnIPv6Host() {
        let authority = { GatewayHTTPClient.authority(of: URL(string: $0)!) }
        XCTAssertEqual(authority("https://gw.example/v1/"), "gw.example")
        XCTAssertEqual(authority("https://gw.example:8443/v1/"), "gw.example:8443")
        XCTAssertEqual(authority("https://[2001:db8::1]:8443/v1/"), "[2001:db8::1]:8443")
        XCTAssertEqual(authority("https://[2001:db8::1]/v1/"), "[2001:db8::1]")
    }

    func testABaseURLIsADirectory() {
        let directory = { GatewayHTTPClient.directory(URL(string: $0)!).absoluteString }
        XCTAssertEqual(directory("https://gw.example/v1"), "https://gw.example/v1/")
        XCTAssertEqual(directory("https://gw.example/v1/"), "https://gw.example/v1/")
        XCTAssertEqual(directory("https://gw.example"), "https://gw.example")
    }

    func testACallerAuthorizedVerifierIsRefused() async throws {
        let authorizing = try Verifier(configAuthorizer: { _ in })
        for (verifier, pin) in [(authorizing, nil), (nil, authorizing)] as [(Verifier?, Verifier?)] {
            do {
                _ = try await GatewayHTTPClient(
                    modelPins: ["m": ModelPin(repo: "tinfoilsh/model", verifier: pin)],
                    verifier: verifier,
                    userCacheSecret: "pinned",
                    catalog: { [:] }
                )
                XCTFail("expected the refusal")
            } catch TinfoilError.configurationError(let failure) {
                XCTAssertTrue(failure.message.contains("caller-authorized config requires a direct enclave client"), failure.message)
            }
        }
    }

    func testTheDefaultsNameTinfoilsGateway() async throws {
        let client = try await GatewayHTTPClient(userCacheSecret: "pinned", catalog: { [:] })
        XCTAssertEqual(client.baseURL.absoluteString, "https://inference-gateway.tinfoil.sh/v1/")
        let models = try await client.models()
        XCTAssertEqual(models, [])
        let openAI = try GatewayOpenAIClient(httpClient: client, apiKey: "test-key")
        XCTAssertEqual(openAI.openAI.configuration.host, "inference-gateway.tinfoil.sh")
        XCTAssertEqual(openAI.openAI.configuration.basePath, "/v1")
    }

    // MARK: - Live

    /// Fetches the gateway's catalog and verifies a replica through it, which
    /// needs no API key.
    func testLiveGatewayVerifiesAReplica() async throws {
        try requireLiveIntegration()
        let results = Box<[Result<Verification, TinfoilError>]>(value: [])
        let client = try await GatewayHTTPClient(
            userCacheSecret: "test-secret",
            onVerificationResult: { results.value.append($0) }
        )
        let models = try await client.models()
        let model = try XCTUnwrap(models.first, "the gateway's catalog lists no routable model")

        let verification = try await client.ensureVerified(model: model)

        XCTAssertTrue(verification.configRepo.hasPrefix("tinfoilsh/"), verification.configRepo)
        XCTAssertFalse(verification.hpkePublicKey.isEmpty, "Gateway replicas seal with EHBP.")
        let current = await client.current
        XCTAssertEqual(current.count, 1)
        XCTAssertEqual(current.first?.verification, verification)
        XCTAssertEqual(current.first?.pinnedModel, "")
        if case .success = results.value.last {} else {
            XCTFail("the verification should be reported, got \(results.value)")
        }
        await client.close()
    }

    /// A chat through the gateway, sealed to a verified replica. It needs
    /// TINFOIL_API_KEY.
    func testLiveGatewayChat() async throws {
        try requireLiveIntegration()
        guard let apiKey = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"], !apiKey.isEmpty else {
            throw XCTSkip("set TINFOIL_API_KEY to send inference through the gateway")
        }
        let client = try await GatewayOpenAIClient(
            userCacheSecret: "test-secret",
            apiKey: apiKey
        )
        let models = try await client.httpClient.models()
        let model = try XCTUnwrap(models.first { $0.contains("llama") || $0.contains("gpt-oss") } ?? models.first)
        let result = try await client.chats(query: ChatQuery(
            messages: [.user(.init(content: .string("Reply with the single word: ready")))],
            model: model
        ))
        XCTAssertFalse((result.choices.first?.message.content ?? "").isEmpty)
        let current = await client.httpClient.current
        XCTAssertEqual(current.first?.models, [model])
    }
}

/// Every public gateway type is marked experimental in its documentation,
/// and this list pins which they are.
final class GatewayExperimentalSurfaceTests: XCTestCase {
    func testEveryGatewayExportIsMarkedExperimental() throws {
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/Tinfoil")
        let files = try FileManager.default.contentsOfDirectory(at: sources.appendingPathComponent("Gateway"), includingPropertiesForKeys: nil)
            + ["GatewayHTTPClient.swift", "GatewayOpenAIClient.swift"].map { sources.appendingPathComponent("Clients/\($0)") }
        var exports: Set<String> = []
        for file in files {
            let lines = try String(contentsOf: file, encoding: .utf8).components(separatedBy: "\n")
            for (index, line) in lines.enumerated() {
                let words = line.split(separator: " ")
                guard words.first == "public", let kind = words.dropFirst().first(where: { ["class", "struct", "enum", "typealias", "protocol"].contains($0) }),
                      let nameIndex = words.firstIndex(of: kind).map({ $0 + 1 }), nameIndex < words.count
                else {
                    continue
                }
                let name = String(words[nameIndex].prefix { $0.isLetter || $0.isNumber })
                exports.insert(name)
                let documentation = lines[..<index].reversed().prefix { $0.hasPrefix("///") }
                XCTAssertTrue(documentation.contains { $0.contains("Experimental:") }, "\(name) is not marked experimental")
            }
        }
        XCTAssertEqual(exports, ["CatalogEntry", "Catalog", "ModelPin", "ReplicaVerification", "GatewayHTTPClient", "GatewayOpenAIClient"])
    }
}
