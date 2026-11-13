import XCTest
import Foundation
@testable import Tinfoil

/// The gateway router over stand-in replicas: which replica a request is
/// sealed to, failing over, following the gateway's reroutes, the policy's
/// pins, and closing.
final class GatewayRouterTests: XCTestCase {
    private static let base = URL(string: "https://gw.example/v1/")!

    /// A replica that verifies unless told not to and answers each send from
    /// a script, recording what it was sent.
    final class FakeReplica: GatewayReplica, @unchecked Sendable {
        let replica: GatewayRouter.Replica
        private let lock = NSLock()
        private var _sent: [URLRequest] = []
        private var _verified: Verification?
        private var _closed = false
        let fails: Bool
        let respond: @Sendable (URLRequest) -> (Int, [String: String])

        init(_ replica: GatewayRouter.Replica, fails: Bool, respond: @escaping @Sendable (URLRequest) -> (Int, [String: String])) {
            self.replica = replica
            self.fails = fails
            self.respond = respond
        }

        var sent: [URLRequest] { lock.withLock { _sent } }
        var closed: Bool { lock.withLock { _closed } }

        func usableVerification() async throws -> Verification {
            if fails {
                throw TinfoilError.attestation("\(replica.host) failed verification")
            }
            let verification = Verification.stub(repo: replica.reference)
            lock.withLock { _verified = verification }
            return verification
        }

        func open(_ request: URLRequest) async throws -> RecoverableResponse {
            lock.withLock { _sent.append(request) }
            let (status, headers) = respond(request)
            return RecoverableResponse(
                response: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!,
                recoveryToken: nil,
                body: AsyncThrowingStream { $0.yield(Data("from \(self.replica.host)".utf8)); $0.finish() }
            )
        }

        var current: Verification? {
            get async { lock.withLock { _verified } }
        }

        func close() async {
            lock.withLock { _closed = true }
        }
    }

    /// Builds routers and keeps the replicas they make.
    final class Harness: @unchecked Sendable {
        private let lock = NSLock()
        private var _replicas: [FakeReplica] = []
        private var _catalogReads = 0
        var failing: Set<String> = []
        var respond: @Sendable (URLRequest) -> (Int, [String: String]) = { _ in (200, [:]) }
        var catalog: Catalog = [
            "m": CatalogEntry(repo: "tinfoilsh/model-repo", hosts: ["a.example", "b.example", "c.example", "d.example"]),
            "other": CatalogEntry(repo: "tinfoilsh/other-repo", hosts: ["o.example"]),
        ]

        var replicas: [FakeReplica] { lock.withLock { _replicas } }
        var catalogReads: Int { lock.withLock { _catalogReads } }

        /// Hosts that a request was sealed to, in order
        var sealedTo: [String] {
            replicas.flatMap { replica in replica.sent.map { _ in replica.replica.host } }
        }

        func router(
            pins: [String: (repo: String, attestor: Attestor?)] = [:],
            pinnedOnly: Bool = false,
            attestor: Attestor = Attestor(verifier: FakeVerifier())
        ) throws -> GatewayRouter {
            try GatewayRouter(
                baseURL: GatewayRouterTests.base,
                policy: GatewayPolicy(pins: pins, pinnedOnly: pinnedOnly, attestor: attestor),
                catalog: {
                    self.lock.withLock { self._catalogReads += 1 }
                    return self.catalog
                },
                secret: "",
                makeReplica: { replica, _ in
                    let fake = FakeReplica(replica, fails: self.failing.contains(replica.host), respond: self.respond)
                    self.lock.withLock { self._replicas.append(fake) }
                    return fake
                }
            )
        }
    }

    private func chat(_ model: String = "m", prefix: String? = nil) -> URLRequest {
        var request = URLRequest(url: URL(string: "chat/completions", relativeTo: Self.base)!)
        request.httpMethod = "POST"
        request.httpBody = Data(#"{"model":"\#(model)","messages":[]}"#.utf8)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let prefix {
            request.setValue(prefix, forHTTPHeaderField: GatewayRequest.cachePrefixHeader)
        }
        return request
    }

    private func assertError(
        _ expected: (TinfoilError) -> Bool,
        _ body: () async throws -> Any,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        do {
            _ = try await body()
            XCTFail("expected an error", file: file, line: line)
        } catch let error as TinfoilError {
            XCTAssertTrue(expected(error), "\(error)", file: file, line: line)
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
        }
    }

    // MARK: - Ranking

    /// The order tinfoil-go ranks the same hosts in, so that every SDK keeps a
    /// conversation on the same replica.
    func testRendezvousRankingMatchesGo() {
        let hosts = ["a.example", "b.example", "c.example", "d.example"]
        XCTAssertEqual(GatewayRouter.rank(hosts, prefix: "prefix-1", first: ""), ["a.example", "b.example", "d.example", "c.example"])
        XCTAssertEqual(GatewayRouter.rank(hosts, prefix: "m", first: ""), ["d.example", "b.example", "c.example", "a.example"])
        XCTAssertEqual(GatewayRouter.rank(hosts, prefix: "m", first: "c.example"), ["c.example", "d.example", "b.example", "a.example"])
        XCTAssertEqual(GatewayRouter.rank(hosts, prefix: "m", first: "elsewhere.example"), ["d.example", "b.example", "c.example", "a.example"])
        XCTAssertEqual(Set(GatewayRouter.rank(hosts, prefix: "", first: "")), Set(hosts))
    }

    // MARK: - Routing

    func testARequestIsSealedToAVerifiedReplicaOfItsModel() async throws {
        let harness = Harness()
        let router = try harness.router()
        let response = try await router.open(chat(prefix: "m"))

        XCTAssertEqual(response.response.statusCode, 200)
        let replica = try XCTUnwrap(harness.replicas.first)
        XCTAssertEqual(replica.replica, GatewayRouter.Replica(host: "d.example", reference: "tinfoilsh/model-repo", pinnedModel: ""))
        let sent = try XCTUnwrap(replica.sent.first)
        XCTAssertEqual(sent.value(forHTTPHeaderField: GatewayRequest.sealHeader), "d.example")
        XCTAssertEqual(sent.value(forHTTPHeaderField: GatewayRequest.modelHeader), "m")
        XCTAssertEqual(sent.url?.absoluteString, "https://gw.example/v1/chat/completions")

        let current = await router.current
        XCTAssertEqual(current.map(\.host), ["d.example"])
        XCTAssertEqual(current.first?.models, ["m"])
        XCTAssertEqual(current.first?.reference, "tinfoilsh/model-repo")
    }

    func testAReplicaThatFailsVerificationIsSkipped() async throws {
        let harness = Harness()
        harness.failing = ["d.example", "b.example"]
        let router = try harness.router()
        _ = try await router.open(chat(prefix: "m"))
        XCTAssertEqual(harness.sealedTo, ["c.example"], "Nothing is sealed to a replica that failed verification.")
    }

    func testWhenNoReplicaVerifiesTheLastFailureIsThrown() async throws {
        let harness = Harness()
        harness.failing = ["a.example", "b.example", "c.example", "d.example"]
        let router = try harness.router()
        await assertError({ $0.message == "a.example failed verification" }) { try await router.open(self.chat(prefix: "m")) }
        XCTAssertTrue(harness.sealedTo.isEmpty)
    }

    func testTheGatewaysRerouteIsFollowedAndRemembered() async throws {
        let harness = Harness()
        harness.respond = { request in
            request.value(forHTTPHeaderField: GatewayRequest.sealHeader) == "d.example"
                ? (412, [GatewayRequest.sealHeader: "a.example"])
                : (200, [:])
        }
        let router = try harness.router()
        let response = try await router.open(chat(prefix: "m"))
        XCTAssertEqual(response.response.statusCode, 200)
        XCTAssertEqual(harness.sealedTo, ["d.example", "a.example"], "The request is sealed again to the replica the gateway chose.")

        _ = try await router.open(chat(prefix: "m"))
        XCTAssertEqual(harness.sealedTo.last, "a.example", "The reroute is remembered for the prefix.")
        XCTAssertEqual(harness.sealedTo.filter { $0 == "d.example" }.count, 1)
    }

    func testAReplicaTheGatewayReroutesToIsVerifiedFirst() async throws {
        let harness = Harness()
        harness.failing = ["a.example"]
        harness.respond = { _ in (412, [GatewayRequest.sealHeader: "a.example"]) }
        let router = try harness.router()
        await assertError({ $0.message == "following gateway route to enclave a.example: a.example failed verification" }) {
            try await router.open(self.chat(prefix: "m"))
        }
        XCTAssertEqual(harness.sealedTo, ["d.example"])
    }

    func testReroutesAreBounded() async throws {
        let harness = Harness()
        let hosts = ["a.example", "b.example", "c.example", "d.example", "e.example"]
        harness.respond = { request in
            let sealed = request.value(forHTTPHeaderField: GatewayRequest.sealHeader) ?? ""
            let next = hosts[((hosts.firstIndex(of: sealed) ?? 0) + 1) % hosts.count]
            return (412, [GatewayRequest.sealHeader: next])
        }
        let router = try harness.router()
        await assertError({
            if case .networkError = $0 { return $0.message.hasPrefix("gateway kept routing away") }
            return false
        }) { try await router.open(self.chat(prefix: "m")) }
        XCTAssertEqual(harness.sealedTo.count, 1 + GatewayRouter.maximumSealRedirects)
    }

    /// A caller that cancels while its request is out isn't sent again when
    /// the gateway reroutes it.
    func testACancelledRequestIsNotResentAfterAReroute() async throws {
        let harness = Harness()
        harness.respond = { _ in
            withUnsafeCurrentTask { $0?.cancel() }
            return (412, [GatewayRequest.sealHeader: "a.example"])
        }
        let router = try harness.router()
        do {
            _ = try await router.open(chat(prefix: "m"))
            XCTFail("expected the cancellation")
        } catch is CancellationError {
        }
        XCTAssertEqual(harness.sealedTo, ["d.example"])
    }

    func testA412WithoutAnotherReplicaIsReturned() async throws {
        let harness = Harness()
        harness.respond = { request in (412, [GatewayRequest.sealHeader: request.value(forHTTPHeaderField: GatewayRequest.sealHeader)!]) }
        let response = try await harness.router().open(chat(prefix: "m"))
        XCTAssertEqual(response.response.statusCode, 412)
        XCTAssertEqual(harness.sealedTo.count, 1)
    }

    func testAnUpgradeIsRefusedBeforeTheCatalogIsRead() async throws {
        let harness = Harness()
        var request = chat()
        request.setValue("websocket", forHTTPHeaderField: "Upgrade")
        let router = try harness.router()
        await assertError({ if case .configurationError = $0 { return true }; return false }) { try await router.open(request) }
        XCTAssertEqual(harness.catalogReads, 0)
    }

    func testEnsureVerifiedTriesReplicasInTheModelsOrder() async throws {
        let harness = Harness()
        harness.failing = ["d.example"]
        let router = try harness.router()
        let verification = try await router.ensureVerified(model: "m")
        XCTAssertEqual(verification.configRepo, "tinfoilsh/model-repo")
        XCTAssertEqual(harness.replicas.map(\.replica.host), ["d.example", "b.example"])
        XCTAssertTrue(harness.sealedTo.isEmpty, "Verifying sends nothing.")
    }

    // MARK: - Policy

    func testModelsListsWhatThePolicyServes() async throws {
        let harness = Harness()
        harness.catalog["tagged"] = CatalogEntry(repo: "tinfoilsh/x@v1", hosts: ["t.example"])
        harness.catalog["foreign"] = CatalogEntry(repo: "someone/x", hosts: ["f.example"])
        harness.catalog["empty"] = CatalogEntry(repo: "tinfoilsh/x", hosts: [])
        harness.catalog["malformed"] = CatalogEntry(repo: "tinfoilsh/", hosts: ["x.example"])
        let all = try await harness.router().models()
        XCTAssertEqual(all, ["m", "other"])
        let pinned = try await harness.router(pins: ["m": ("tinfoilsh/model-repo@v1", nil)], pinnedOnly: true).models()
        XCTAssertEqual(pinned, ["m"])
    }

    func testAPinnedModelIsVerifiedAgainstItsPin() async throws {
        let harness = Harness()
        let router = try harness.router(pins: ["m": ("tinfoilsh/model-repo@v2", nil)])
        _ = try await router.open(chat(prefix: "m"))
        XCTAssertEqual(harness.replicas.first?.replica, GatewayRouter.Replica(host: "d.example", reference: "tinfoilsh/model-repo@v2", pinnedModel: "m"))
        let current = await router.current
        XCTAssertEqual(current.first?.pinnedModel, "m")
    }

    func testAGatewayOfferingAnotherRepositoryForAPinIsRefused() async throws {
        let harness = Harness()
        let router = try harness.router(pins: ["m": ("tinfoilsh/expected", nil)])
        await assertError({
            if case .attestationError = $0 {
                return $0.message == #"model "m": expected repository "tinfoilsh/expected", gateway offered "tinfoilsh/model-repo""#
            }
            return false
        }) { try await router.open(self.chat(prefix: "m")) }
        XCTAssertTrue(harness.replicas.isEmpty)
    }

    func testRequestsForUnservedModelsAreRefused() async throws {
        let harness = Harness()
        let pinnedOnly = try harness.router(pins: ["other": ("tinfoilsh/other-repo", nil)], pinnedOnly: true)
        await assertError({ $0.message == #"model "m" is not pinned"# }) { try await pinnedOnly.open(self.chat()) }
        await assertError({
            $0.message == #"model "missing" has no valid bare tinfoilsh/ repository with replicas in the gateway catalog"#
        }) { try await harness.router().open(self.chat("missing")) }
        XCTAssertTrue(harness.replicas.isEmpty)
    }

    func testThePolicyIsCheckedUpFront() {
        let message = { (body: () throws -> Any) -> String? in
            do {
                _ = try body()
                return nil
            } catch let error as TinfoilError {
                return error.message
            } catch {
                return "\(error)"
            }
        }
        let authorizing = Attestor(verifier: FakeVerifier(callerAuthorizesConfig: true))
        let refusing = Attestor(verifier: FakeVerifier(refusedRepo: "tinfoilsh/bad"))
        XCTAssertEqual(message { try GatewayPolicy(pins: [:], pinnedOnly: true, attestor: refusing) },
                       "pinned-only mode requires at least one model pin")
        XCTAssertEqual(message { try GatewayPolicy(pins: [:], pinnedOnly: false, attestor: authorizing) },
                       "caller-authorized config requires a direct enclave client")
        XCTAssertEqual(message { try GatewayPolicy(pins: ["m": ("tinfoilsh/x", authorizing)], pinnedOnly: false, attestor: refusing) },
                       #"model "m": caller-authorized config requires a direct enclave client"#)
        XCTAssertEqual(message { try GatewayPolicy(pins: ["m": ("someone/x", nil)], pinnedOnly: false, attestor: refusing) },
                       #"model pin "m" repository "someone/x" must belong to tinfoilsh/"#)
        XCTAssertEqual(message { try GatewayPolicy(pins: [" ": ("tinfoilsh/x", nil)], pinnedOnly: false, attestor: refusing) },
                       #"model pin " " repository "tinfoilsh/x" must belong to tinfoilsh/"#)
        XCTAssertEqual(message { try GatewayPolicy(pins: ["m": ("tinfoilsh/bad", nil)], pinnedOnly: false, attestor: refusing) },
                       #"model "m": repo tinfoilsh/bad cannot be verified"#)
    }

    // MARK: - Closing

    func testAClosedRouterRefusesAndClosesItsReplicas() async throws {
        let harness = Harness()
        let router = try harness.router()
        _ = try await router.open(chat(prefix: "m"))
        let reads = harness.catalogReads

        await router.close()

        XCTAssertTrue(harness.replicas.allSatisfy(\.closed))
        let closed = { (error: TinfoilError) in error.message == "the client is closed" }
        await assertError(closed) { try await router.open(self.chat(prefix: "m")) }
        await assertError(closed) { try await router.models() }
        await assertError(closed) { try await router.ensureVerified(model: "m") }
        XCTAssertEqual(harness.catalogReads, reads)
        XCTAssertEqual(harness.sealedTo.count, 1)
    }
}

/// The catalog cache and fetch.
final class GatewayCatalogTests: XCTestCase {
    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var _now = ContinuousClock.now
        var now: ContinuousClock.Instant { lock.withLock { _now } }
        func advance(_ duration: Duration) { lock.withLock { _now += duration } }
    }

    final class Source: @unchecked Sendable {
        private let lock = NSLock()
        private var _fetches = 0
        var fail = false
        var model = "first"
        var fetches: Int { lock.withLock { _fetches } }

        func fetch() throws -> Catalog {
            let (fail, model) = lock.withLock { () -> (Bool, String) in
                _fetches += 1
                return (self.fail, self.model)
            }
            if fail {
                throw TinfoilError.network("catalog unavailable")
            }
            return [model: CatalogEntry(repo: "tinfoilsh/r", hosts: ["h"])]
        }
    }

    func testTheFirstFetchIsAwaitedAndAFailureRetried() async throws {
        let source = Source()
        source.fail = true
        let cache = CatalogCache(fetch: { try source.fetch() })
        do {
            _ = try await cache.get()
            XCTFail("expected the failure")
        } catch {}
        source.fail = false
        let catalog = try await cache.get()
        XCTAssertEqual(Array(catalog.keys), ["first"])
        XCTAssertEqual(source.fetches, 2)
    }

    func testARefreshRunsBehindTheCachedCatalog() async throws {
        let source = Source()
        let clock = Clock()
        let cache = CatalogCache(fetch: { try source.fetch() }, now: { clock.now })
        _ = try await cache.get()
        _ = try await cache.get()
        XCTAssertEqual(source.fetches, 1, "Within the interval the catalog is reused.")

        source.model = "second"
        clock.advance(.seconds(11))
        let stale = try await cache.get()
        XCTAssertEqual(Array(stale.keys), ["first"], "A refresh doesn't hold up the caller.")
        try await eventually { try await cache.get().keys.first == "second" }
        XCTAssertEqual(source.fetches, 2)

        source.fail = true
        clock.advance(.seconds(11))
        _ = try await cache.get()
        try await eventually { source.fetches == 3 }
        // Whether or not the failed refresh has finished, the cache returns
        // the last catalog and starts no other refresh within the interval.
        let kept = try await cache.get()
        XCTAssertEqual(Array(kept.keys), ["second"], "A failed refresh keeps the last catalog.")
        XCTAssertEqual(source.fetches, 3)
    }

    /// Waits, with a generous deadline, for a refresh that runs behind the
    /// cache to have the effect `condition` checks.
    private func eventually(_ condition: () async throws -> Bool, file: StaticString = #filePath, line: UInt = #line) async throws {
        let deadline = ContinuousClock.now + .seconds(10)
        while ContinuousClock.now < deadline {
            if try await condition() {
                return
            }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTFail("timed out waiting for the refresh", file: file, line: line)
    }

    func testFetchRefusesAHostThatIsNotAnAuthority() async {
        for host in ["", "gw.example/x", "user@gw.example", "gw.example?q", "gw.example#f", "https://gw.example"] {
            do {
                _ = try await GatewayCatalog.fetch(host: host) { url in
                    XCTFail("fetched \(url) for the host \(host)")
                    return Data()
                }
                XCTFail("\(host) must be refused")
            } catch TinfoilError.configurationError {
            } catch {
                XCTFail("unexpected \(error)")
            }
        }
    }

    func testFetchKeepsOnlyRoutableEntries() async throws {
        let body = #"""
        {
          "good": {"repo": "tinfoilsh/good", "hosts": ["g.example"]},
          "tagged": {"repo": "tinfoilsh/good@v1", "hosts": ["g.example"]},
          "foreign": {"repo": "someone/x", "hosts": ["f.example"]},
          "empty": {"repo": "tinfoilsh/x", "hosts": []}
        }
        """#
        let requested = Box<URL?>(value: nil)
        let catalog = try await GatewayCatalog.fetch(host: "gw.example:8443") { url in
            requested.value = url
            return Data(body.utf8)
        }
        XCTAssertEqual(catalog, ["good": CatalogEntry(repo: "tinfoilsh/good", hosts: ["g.example"])])
        XCTAssertEqual(requested.value?.absoluteString, "https://gw.example:8443/catalog")

        do {
            _ = try await GatewayCatalog.fetch(host: "gw.example") { _ in Data("not json".utf8) }
            XCTFail("expected a decoding failure")
        } catch TinfoilError.networkError(let failure) {
            XCTAssertTrue(failure.message.hasPrefix("decoding gateway catalog"), failure.message)
        }
    }
}
