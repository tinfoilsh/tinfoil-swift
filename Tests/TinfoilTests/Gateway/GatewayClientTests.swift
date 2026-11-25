import XCTest
import Foundation
import OpenAI
@testable import Tinfoil

/// The public gateway clients: the configuration checks that come before any
/// network I/O, and live runs against Tinfoil's gateway.
final class GatewayClientTests: XCTestCase {
    /// A valid pin set for tests in which the pinned model is never requested
    private static let pins = ["pinned": ModelPin(repo: "tinfoilsh/pinned")]

    private func assertRefusedBeforeIO(
        _ expected: String,
        modelPins: [String: ModelPin] = GatewayClientTests.pins,
        policy: Policy = Policy(),
        url: URL? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await GatewayHTTPClient(
                options: .init(modelPins: modelPins, url: url, policy: policy, userCacheSecret: "test-secret", catalog: {
                    XCTFail("the catalog was read despite a refused configuration", file: file, line: line)
                    return [:]
                })
            )
            XCTFail("expected \(expected)", file: file, line: line)
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains(expected), "\(failure.message) should mention \(expected)", file: file, line: line)
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
        }
    }

    func testTheConfigurationIsCheckedBeforeAnyNetworkIO() async {
        await assertRefusedBeforeIO("the gateway URL must use HTTPS", url: URL(string: "http://localhost/v1/")!)
        await assertRefusedBeforeIO("must not carry a query or a fragment", url: URL(string: "https://gw.example/v1/?")!)
        await assertRefusedBeforeIO("must not carry a query or a fragment", url: URL(string: "https://gw.example/v1/#x")!)
        await assertRefusedBeforeIO("carry no credentials", url: URL(string: "https://user:pass@gw.example/v1/")!)
        await assertRefusedBeforeIO("requires at least one model pin", modelPins: [:])
        await assertRefusedBeforeIO("must belong to tinfoilsh/", modelPins: ["m": ModelPin(repo: "someone/model")])
        await assertRefusedBeforeIO(#"model "m""#, modelPins: ["m": ModelPin(repo: "tinfoilsh/")])
        await assertRefusedBeforeIO("freshness maximum age", modelPins: ["m": ModelPin(repo: "tinfoilsh/model", policy: Policy(freshnessMaxAge: -1))])
        // The gateway's policy is checked even when every pin sets its own.
        await assertRefusedBeforeIO(
            "freshness maximum age",
            modelPins: ["m": ModelPin(repo: "tinfoilsh/model", policy: Policy())],
            policy: Policy(freshnessMaxAge: -1)
        )
    }

    func testAnUnpinnedModelIsRefusedWithoutContactingAReplica() async throws {
        let client = try await GatewayHTTPClient(options: .init(
            modelPins: Self.pins,
            url: URL(string: "https://gw.example/v1/")!,
            userCacheSecret: "test-secret",
            catalog: {
                [
                    "pinned": CatalogEntry(repo: "tinfoilsh/pinned", hosts: ["p.example"]),
                    "unpinned": CatalogEntry(repo: "tinfoilsh/unpinned", hosts: ["u.example"]),
                ]
            }
        ))
        let isUnpinned = { (error: Error) -> Bool in
            if case TinfoilError.configurationError(let failure) = error {
                return failure.message == #"model "unpinned" is not pinned"#
            }
            return false
        }
        do {
            _ = try await client.ensureVerified(model: "unpinned")
            XCTFail("a model that the catalog lists but that has no pin should be refused")
        } catch {
            XCTAssertTrue(isUnpinned(error), "\(error)")
        }
        var request = URLRequest(url: URL(string: "chat/completions", relativeTo: client.baseURL)!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(#"{"model":"unpinned","messages":[]}"#.utf8)
        do {
            _ = try await client.data(for: request)
            XCTFail("a request for an unpinned model should be refused")
        } catch {
            XCTAssertTrue(isUnpinned(error), "\(error)")
        }
        let models = try await client.models()
        XCTAssertEqual(models, ["pinned"])
        let attempts = await client.replicas
        XCTAssertTrue(attempts.isEmpty, "No replica is contacted for an unpinned model.")
        await client.close()
    }

    /// A gateway that records every URL that the client fetches: the
    /// catalog, and each replica's attestation document through the relay.
    private func recordingGateway(url: URL?, urls: Recorder<URL>) async throws -> GatewayHTTPClient {
        try await GatewayHTTPClient(
            options: .init(modelPins: ["m": ModelPin(repo: "tinfoilsh/model-repo")], url: url, userCacheSecret: "test-secret"),
            get: { url in
                urls.record(url)
                if url.path.hasSuffix("/catalog") {
                    return Data(#"{"m":{"repo":"tinfoilsh/model-repo","hosts":["replica.example"]}}"#.utf8)
                }
                return Data(FakeNetwork.document("ok", for: url).utf8)
            },
            verifier: { _ in FakeVerifier() }
        )
    }

    /// The URL is the gateway's root: the catalog, the attestation relay and
    /// the OpenAI client's API path join under its path, whether or not it
    /// ends with a slash.
    func testTheCatalogTheRelayAndTheAPIPathJoinUnderTheGatewayURL() async throws {
        let cases: [(url: String?, root: String)] = [
            (nil, "https://inference-gateway.tinfoil.sh/"),
            ("https://gw.example", "https://gw.example/"),
            ("https://gw.example/", "https://gw.example/"),
            ("https://gw.example:8443/relay", "https://gw.example:8443/relay/"),
            ("https://gw.example:8443/relay/", "https://gw.example:8443/relay/"),
        ]
        for (url, root) in cases {
            let urls = Recorder<URL>()
            let client = try await recordingGateway(url: url.map { URL(string: $0)! }, urls: urls)
            let report = try await client.ensureVerified(model: "m")
            XCTAssertEqual(report.metadata.host, "replica.example")

            let fetched = urls.values.map(\.absoluteString)
            XCTAssertEqual(fetched.first, root + "catalog", "\(url ?? "default")")
            let relayed = try XCTUnwrap(fetched.dropFirst().first, "\(url ?? "default")")
            XCTAssertTrue(
                relayed.hasPrefix(root + ".well-known/tinfoil-attestation?nonce=") && relayed.hasSuffix("&enclave=replica.example"),
                relayed
            )
            XCTAssertEqual(fetched.count, 2, "Nothing else is fetched: \(fetched)")

            let openAI = try OpenAIClient(httpClient: client, apiKey: "k")
            XCTAssertEqual(openAI.baseURL.absoluteString, root + "v1/")
            let custom = try OpenAIClient(httpClient: client, apiPath: "/openai/v1", apiKey: "k")
            XCTAssertEqual(custom.baseURL.absoluteString, root + "openai/v1/")
            await client.close()
        }
    }

    func testABaseURLIsADirectory() {
        let directory = { GatewayHTTPClient.directory(URL(string: $0)!).absoluteString }
        XCTAssertEqual(directory("https://gw.example/v1"), "https://gw.example/v1/")
        XCTAssertEqual(directory("https://gw.example/v1/"), "https://gw.example/v1/")
        XCTAssertEqual(directory("https://gw.example"), "https://gw.example")
    }

    func testTheDefaultsNameTinfoilsGateway() async throws {
        let client = try await GatewayHTTPClient(options: .init(modelPins: Self.pins, userCacheSecret: "pinned", catalog: { [:] }))
        XCTAssertEqual(client.baseURL.absoluteString, "https://inference-gateway.tinfoil.sh/")
        let models = try await client.models()
        XCTAssertEqual(models, [])
        let openAI = try OpenAIClient(httpClient: client, apiKey: "test-key")
        XCTAssertEqual(openAI.openAI.configuration.host, "inference-gateway.tinfoil.sh")
        XCTAssertEqual(openAI.openAI.configuration.timeoutInterval, 60, "The default idle timeout")
        let patient = try OpenAIClient(httpClient: client, apiKey: "test-key", timeoutInterval: 600)
        XCTAssertEqual(patient.openAI.configuration.timeoutInterval, 600)
        XCTAssertEqual(openAI.openAI.configuration.basePath, "/v1")
    }

    // MARK: - Live

    /// One snapshot of the live gateway's catalog. A test pins every model
    /// in it and gives the client the same snapshot, so that the two can't
    /// drift apart.
    private func liveCatalog() async throws -> Catalog {
        let host = try XCTUnwrap(GatewayHTTPClient.defaultURL.host)
        return try await GatewayHTTPClient.fetchCatalog(host: host)
    }

    /// Fetches the gateway's catalog and verifies a replica through it, which
    /// needs no API key.
    func testLiveGatewayVerifiesAReplica() async throws {
        try requireLiveIntegration()
        let results = Recorder<(String, Result<VerificationReport, TinfoilError>)>()
        let catalog = try await liveCatalog()
        let client = try await GatewayHTTPClient(options: .init(
            modelPins: catalog.mapValues { ModelPin(repo: $0.repo) },
            userCacheSecret: "test-secret",
            onVerificationAttempt: { results.record(($0, $1)) },
            catalog: { catalog }
        ))
        let models = try await client.models()
        let model = try XCTUnwrap(models.first, "the gateway's catalog lists no routable model")

        let report = try await client.ensureVerified(model: model)
        let verification = try XCTUnwrap(report.verifiedFacts)

        XCTAssertTrue(verification.configRepo.hasPrefix("tinfoilsh/"), verification.configRepo)
        XCTAssertFalse(verification.hpkePublicKey.isEmpty, "Gateway replicas seal with EHBP.")
        let current = await client.replicas
        XCTAssertEqual(current.count, 1)
        XCTAssertEqual(current.first?.lastAttempt.report, report)
        XCTAssertEqual(current.first?.pinnedModel, model)
        guard let (host, reported) = results.values.last, case .success = reported else {
            return XCTFail("the verification should be reported, got \(results.values)")
        }
        XCTAssertEqual(host, current.first?.host, "The callback names the replica.")
        await client.close()
    }

    /// A chat through the gateway, sealed to a verified replica. It needs
    /// TINFOIL_API_KEY.
    func testLiveGatewayChat() async throws {
        try requireLiveIntegration()
        guard let apiKey = ProcessInfo.processInfo.environment["TINFOIL_API_KEY"], !apiKey.isEmpty else {
            throw XCTSkip("set TINFOIL_API_KEY to send inference through the gateway")
        }
        let catalog = try await liveCatalog()
        let gateway = try await GatewayHTTPClient(options: .init(
            modelPins: catalog.mapValues { ModelPin(repo: $0.repo) },
            userCacheSecret: "test-secret",
            catalog: { catalog }
        ))
        let client = try OpenAIClient(httpClient: gateway, apiKey: apiKey)
        let models = try await gateway.models()
        let model = try XCTUnwrap(models.first { $0.contains("llama") || $0.contains("gpt-oss") } ?? models.first)
        let result = try await client.chats(query: ChatQuery(
            messages: [.user(.init(content: .string("Reply with the single word: ready")))],
            model: model
        ))
        XCTAssertFalse((result.choices.first?.message.content ?? "").isEmpty)
        let current = await gateway.replicas
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
            + ["GatewayHTTPClient.swift"].map { sources.appendingPathComponent("Clients/\($0)") }
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
        XCTAssertEqual(exports, ["CatalogEntry", "Catalog", "ModelPin", "ReplicaVerification", "GatewayHTTPClient", "GatewayOptions"])
    }
}
