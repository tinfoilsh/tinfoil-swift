import XCTest
import CryptoKit
import Foundation
@testable import Tinfoil

/// Exercises a trust and a policy through the real TinfoilGo framework: each
/// option reaching it, the checks a client makes before any I/O, and a config
/// authorizer called back from Go during verification.
final class PolicyTests: XCTestCase {
    private let key = P256.Signing.PrivateKey().publicKey.pemRepresentation
    private let fixture = ConfigAuthorizerFixture.self

    private func assertConfigurationError(
        _ expression: @autoclosure () throws -> Any,
        containing expected: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            guard case TinfoilError.configurationError(let failure) = error else {
                return XCTFail("expected a configuration error, got \(error)", file: file, line: line)
            }
            XCTAssertTrue(failure.message.contains(expected), "\(failure.message) should mention \(expected)", file: file, line: line)
        }
    }

    /// The framework verifier for `trust` under `policy`
    private func backend(_ trust: Trust?, _ policy: Policy = Policy()) throws -> GoAttestationVerifier {
        try GoAttestationVerifier(trust: trust, policy: policy)
    }

    /// The framework verifier for the default trust under `policy`
    private func backend(_ policy: Policy) throws -> GoAttestationVerifier {
        try backend(nil, policy)
    }

    func testPublicRegistryID() {
        XCTAssertTrue(Trust.publicRegistryID.hasPrefix("https://"), Trust.publicRegistryID)
        XCTAssertNoThrow(try backend(.project("org/project", registryIDs: [Trust.publicRegistryID])))
    }

    func testAcceptsEachOption() throws {
        let register = String(repeating: "ab", count: 48)
        XCTAssertNoThrow(try backend(Policy()))
        XCTAssertNoThrow(try backend(Policy(
            pinnedRegisters: .init(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: ["", "", "", "", register]),
            freshnessMaxAge: 3600
        )))
        XCTAssertNoThrow(try backend(Policy(freshnessMaxAge: 0)), "Zero selects the default.")
        XCTAssertNoThrow(try backend(Policy(freshnessMaxAge: 1e-9)), "One nanosecond is the shortest age accepted.")
        XCTAssertNoThrow(try backend(Policy(artifacts: .endorsed(freshnessKeys: [key]))))
        XCTAssertNoThrow(try backend(Policy(artifacts: .embedded(runtime: fixture.runtime, platform: fixture.platform))))
        XCTAssertNoThrow(try backend(Policy(artifacts: .embedded(runtime: fixture.runtime, freshnessKeys: [key]))))
        XCTAssertNoThrow(try backend(.signedBy(keys: [key])))
        XCTAssertNoThrow(try backend(.embeddedConfig(fixture.config, name: "/org/project/v1")))
        XCTAssertNoThrow(try backend(.authorizedBy { _ in }))
    }

    func testRefusesInvalidOptions() {
        assertConfigurationError(try backend(.project("org/project", registryIDs: ["not a registry"])), containing: "registry URI")
        assertConfigurationError(try backend(.signedBy(keys: [])), containing: "must not be empty")
        assertConfigurationError(try backend(.signedBy(keys: ["not a key"])), containing: "PEM PUBLIC KEY")
        assertConfigurationError(try backend(.embeddedConfig(Data())), containing: "must not be empty")
        assertConfigurationError(try backend(Policy(artifacts: .embedded())), containing: "a runtime or a platform")
        XCTAssertThrowsError(try backend(Policy(artifacts: .embedded(runtime: fixture.runtime, platform: fixture.platform, freshnessKeys: [key]))))
        assertConfigurationError(try backend(Policy(artifacts: .embedded(runtime: Data()))), containing: "must not be empty")
        assertConfigurationError(try backend(Policy(artifacts: .endorsed(freshnessKeys: []))), containing: "must not be empty")
        assertConfigurationError(try backend(Policy(artifacts: .endorsed(freshnessKeys: ["not a key"]))), containing: "PEM PUBLIC KEY")
        assertConfigurationError(
            try backend(Policy(pinnedRegisters: .init(type: "bogus", registers: ["aa"]))),
            containing: "pinned registers"
        )
    }

    func testRefusesAgesThatAreNegativeOrUnrepresentable() {
        // ±1e-10 (a tenth of a nanosecond) rounds to zero nanoseconds, which
        // would otherwise select the default rather than fail.
        for age in [-1, 1e-10, -1e-10, TimeInterval.nan, .infinity, -.infinity, 1e300] {
            assertConfigurationError(try backend(Policy(freshnessMaxAge: age)), containing: "freshness maximum age")
        }
    }

    /// Each kind of trust gives the pin that its verifications are made
    /// against, and one that names nothing is refused, so that a missing
    /// value can't widen the trust by accident.
    func testTrustPins() throws {
        XCTAssertEqual(try Trust.repo("org/repo@v1").pin(), Pin(repo: "org/repo@v1"))
        XCTAssertEqual(try Trust.project("org/project@v1").pin(), Pin(project: "org/project@v1"))
        XCTAssertEqual(try Trust.project("org/project", registryIDs: [Trust.publicRegistryID]).pin(), Pin(project: "org/project"))
        XCTAssertEqual(try Trust.either(repo: "org/repo", project: "org/project").pin(), Pin(repo: "org/repo", project: "org/project"))
        XCTAssertEqual(try Trust.signedBy(keys: [key]).pin(), Pin.none)
        XCTAssertEqual(try Trust.signedBy(keys: [key], project: "org/project").pin(), Pin(project: "org/project"))
        XCTAssertEqual(try Trust.authorizedBy { _ in }.pin(), Pin.none)
        XCTAssertEqual(try Trust.embeddedConfig(fixture.config).pin(), Pin.none)

        assertConfigurationError(try Trust.repo("").pin(), containing: "requires a repository")
        assertConfigurationError(try Trust.project("").pin(), containing: "requires a project")
        assertConfigurationError(try Trust.project("org/project", registryIDs: []).pin(), containing: "must not be empty")
        XCTAssertEqual(try Trust.signedBy(keys: [key], project: "").pin(), Pin.none, "An empty project accepts any config that the keys sign.")
        XCTAssertNil(Trust.signedBy(keys: [key], project: "").project)
        assertConfigurationError(try Trust.either(repo: "", project: "org/project").pin(), containing: "requires both")
        assertConfigurationError(try Trust.either(repo: "org/repo", project: "").pin(), containing: "requires both")

        XCTAssertEqual(Trust.either(repo: "org/repo", project: "org/project").repo, "org/repo")
        XCTAssertEqual(Trust.signedBy(keys: [key], project: "org/project").project, "org/project")
        XCTAssertNil(Trust.project("org/project").repo, "A project is not also read as a repository.")
    }

    /// An invalid trust is refused before any network I/O.
    func testAnInvalidTrustIsRefusedBeforeIO() async {
        for trust in [Trust.repo(""), .project("org/project", registryIDs: []), .signedBy(keys: [])] {
            do {
                _ = try await EnclaveHTTPClient(enclave: "127.0.0.1:9", trust: trust)
                XCTFail("expected a configuration error")
            } catch TinfoilError.configurationError {
            } catch {
                XCTFail("expected a configuration error before any I/O, got \(error)")
            }
        }
    }

    /// A pin that a verifier can never accept is refused before any I/O, each
    /// part in its own namespace.
    func testPinChecksBeforeIO() throws {
        let authorized = try backend(.authorizedBy { _ in })
        XCTAssertNoThrow(try authorized.checkPinVerifiability(Pin.none))
        assertConfigurationError(
            try authorized.checkPinVerifiability(Pin(project: "org/repo")),
            containing: "config authorizer cannot authenticate"
        )

        let embedded = try backend(.embeddedConfig(fixture.config, name: "/org/project/v1"))
        XCTAssertNoThrow(try embedded.checkPinVerifiability(Pin(project: "org/project@v1")))
        assertConfigurationError(
            try embedded.checkPinVerifiability(Pin(project: "org/other")),
            containing: "does not match"
        )
        assertConfigurationError(
            try embedded.checkPinVerifiability(Pin(repo: "org/project")),
            containing: "registry collateral only"
        )

        let defaults = try backend(nil)
        XCTAssertNoThrow(try defaults.checkPinVerifiability(Pin(repo: "org/repo")))
        XCTAssertNoThrow(try defaults.checkPinVerifiability(Pin(project: "org/project")))
        XCTAssertThrowsError(try defaults.checkPinVerifiability(Pin(repo: "not a reference")))
        XCTAssertThrowsError(try defaults.checkPinVerifiability(Pin(project: "not a reference")))
        assertConfigurationError(try defaults.checkPinVerifiability(Pin.none), containing: "pin names nothing")

        assertConfigurationError(
            try EnclaveHTTPClient.connection(
                enclave: "enclave.example",
                pin: Pin(project: "org/repo"),
                transportMode: .ehbp,
                baseURL: nil,
                attestationRelay: nil,
                attestor: Attestor(verifier: authorized, fetch: { url in
                    XCTFail("fetched \(url) despite a pin the verifier refuses")
                    throw TinfoilError.network("unreachable")
                }),
                onVerificationResult: nil
            ),
            containing: "config authorizer cannot authenticate"
        )
    }

    /// Go calls the Swift authorizer during verification with the document's
    /// config, and a rejection fails the document at the provenance layer
    /// with the authorizer's message.
    func testConfigAuthorizerRejects() throws {
        let seen = Seen()
        let verifier = try backend(.authorizedBy { endorsement in
            seen.add(endorsement)
            throw TinfoilError.configuration("config is not on the allow list")
        }, Policy(artifacts: .embedded(runtime: fixture.runtime, platform: fixture.platform)))
        XCTAssertThrowsError(try verifier.verify(document: fixture.document, nonce: fixture.nonce, pin: Pin.none)) { error in
            guard case TinfoilError.attestationError(let failure) = error else {
                return XCTFail("expected an attestation error, got \(error)")
            }
            XCTAssertEqual(failure.layer, .provenance)
            XCTAssertTrue(failure.message.contains("config is not on the allow list"), failure.message)
        }
        XCTAssertEqual(seen.endorsements, [
            ConfigEndorsement(config: fixture.config, reference: "", sigstoreBundle: Data(), issuerCertificate: Data()),
        ])
    }

    /// An approved config lets verification go on, and the fixture's
    /// unauthenticated quote then fails at the quote layer.
    func testConfigAuthorizerApproves() throws {
        let seen = Seen()
        let verifier = try backend(
            .authorizedBy { seen.add($0) },
            Policy(artifacts: .embedded(runtime: fixture.runtime, platform: fixture.platform))
        )
        XCTAssertThrowsError(try verifier.verify(document: fixture.document, nonce: fixture.nonce, pin: Pin.none)) { error in
            guard case TinfoilError.attestationError(let failure) = error else {
                return XCTFail("expected an attestation error, got \(error)")
            }
            XCTAssertEqual(failure.layer, .quote, "Approving a config never bypasses the hardware check.")
        }
        XCTAssertEqual(seen.endorsements.map(\.config), [fixture.config])
    }

    /// Verifications on several threads may call one authorizer at once.
    func testConfigAuthorizerRunsConcurrently() throws {
        let seen = Seen()
        let verifier = try backend(
            .authorizedBy { seen.add($0) },
            Policy(artifacts: .embedded(runtime: fixture.runtime, platform: fixture.platform))
        )
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            _ = try? verifier.verify(document: fixture.document, nonce: fixture.nonce, pin: Pin.none)
        }
        XCTAssertEqual(seen.endorsements.count, 8)
    }
}

/// Records the endorsements an authorizer was called with, from any thread.
private final class Seen: @unchecked Sendable {
    private let lock = NSLock()
    private var _endorsements: [ConfigEndorsement] = []

    var endorsements: [ConfigEndorsement] {
        lock.lock()
        defer { lock.unlock() }
        return _endorsements
    }

    func add(_ endorsement: ConfigEndorsement) {
        lock.lock()
        defer { lock.unlock() }
        _endorsements.append(endorsement)
    }
}
