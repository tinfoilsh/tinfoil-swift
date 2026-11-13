import XCTest
import CryptoKit
import Foundation
@testable import Tinfoil

/// Exercises `Verifier` through the real TinfoilGo framework: each option
/// reaching it, the checks a client makes before any I/O, and a config
/// authorizer called back from Go during verification.
final class VerifierTests: XCTestCase {
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

    func testPublicRegistryID() {
        XCTAssertTrue(Verifier.publicRegistryID.hasPrefix("https://"), Verifier.publicRegistryID)
        XCTAssertNoThrow(try Verifier(configRegistryIDs: [Verifier.publicRegistryID]))
    }

    func testAcceptsEachOption() throws {
        let register = String(repeating: "ab", count: 48)
        XCTAssertNoThrow(try Verifier())
        XCTAssertNoThrow(try Verifier(
            pinnedRegisters: .init(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: ["", "", "", "", register]),
            freshnessMaxAge: 3600
        ))
        XCTAssertNoThrow(try Verifier(freshnessMaxAge: 1e-9), "One nanosecond is the shortest age accepted.")
        XCTAssertNoThrow(try Verifier(configSigningKeys: [key]))
        XCTAssertNoThrow(try Verifier(freshnessSigningKeys: [key]))
        XCTAssertNoThrow(try Verifier(embeddedReferences: .init(runtime: fixture.runtime, platform: fixture.platform)))

        let bytes = try Verifier(embeddedReferences: .init(config: .bytes(fixture.config, name: "/org/project/v1")))
        XCTAssertTrue(bytes.backend.callerAuthorizesConfig)
        let digest = SHA256.hash(data: fixture.config).map { String(format: "%02x", $0) }.joined()
        let runtimeDigest = SHA256.hash(data: fixture.runtime).map { String(format: "%02x", $0) }.joined()
        let reference = try Verifier(embeddedReferences: .init(config: .reference(
            digest: digest,
            runtime: RuntimeReference(repo: "tinfoilsh/cvmimage", tag: "v0.15.0", digest: runtimeDigest)
        )))
        XCTAssertTrue(reference.backend.callerAuthorizesConfig)
        XCTAssertFalse(try Verifier().backend.callerAuthorizesConfig)
    }

    func testRefusesInvalidOptions() {
        assertConfigurationError(try Verifier(configRegistryIDs: []), containing: "must not be empty")
        assertConfigurationError(try Verifier(configRegistryIDs: ["not a registry"]), containing: "registry URI")
        assertConfigurationError(try Verifier(configSigningKeys: []), containing: "must not be empty")
        assertConfigurationError(try Verifier(configSigningKeys: ["not a key"]), containing: "PEM PUBLIC KEY")
        assertConfigurationError(try Verifier(embeddedReferences: .init()), containing: "at least one component")
        assertConfigurationError(try Verifier(embeddedReferences: .init(config: .bytes(Data()))), containing: "must not be empty")
        assertConfigurationError(
            try Verifier(pinnedRegisters: .init(type: "bogus", registers: ["aa"])),
            containing: "pinned registers"
        )
        // The framework's conflicts between trust sources reach Swift.
        assertConfigurationError(
            try Verifier(configRegistryIDs: [Verifier.publicRegistryID], configSigningKeys: [key]),
            containing: "registry ID policy"
        )
        assertConfigurationError(
            try Verifier(configSigningKeys: [key], configAuthorizer: { _ in }),
            containing: "config authorizer conflicts"
        )
        assertConfigurationError(
            try Verifier(embeddedReferences: .init(config: .bytes(fixture.config)), configAuthorizer: { _ in }),
            containing: "config authorizer conflicts"
        )
    }

    func testRefusesAgesThatAreNotPositiveOrUnrepresentable() {
        // Zero, and ±1e-10 (a tenth of a nanosecond), round to zero
        // nanoseconds, which would otherwise select the default rather than fail.
        for age in [0, -1, 1e-10, -1e-10, TimeInterval.nan, .infinity, -.infinity, 1e300] {
            assertConfigurationError(try Verifier(freshnessMaxAge: age), containing: "freshness maximum age")
        }
    }

    /// A repo that a verifier can never accept is refused before any I/O.
    func testRepoChecksBeforeIO() throws {
        let authorized = try Verifier(configAuthorizer: { _ in })
        XCTAssertTrue(authorized.backend.callerAuthorizesConfig)
        XCTAssertNoThrow(try authorized.backend.checkRepoVerifiability(""))
        assertConfigurationError(
            try authorized.backend.checkRepoVerifiability("org/repo"),
            containing: "config authorizer cannot authenticate"
        )
        assertConfigurationError(
            try EnclaveHTTPClient.connection(
                enclave: "enclave.example",
                repo: "org/repo",
                transportMode: .ehbp,
                baseURL: nil,
                attestationRelay: nil,
                userCacheSecret: nil,
                attestor: Attestor(verifier: authorized.backend, fetch: { url in
                    XCTFail("fetched \(url) despite a repo the verifier refuses")
                    throw TinfoilError.network("unreachable")
                }),
                onVerificationResult: nil
            ),
            containing: "config authorizer cannot authenticate"
        )
    }

    /// A verifier that takes the config from the caller can't pick a router.
    func testRouterRefusesCallerAuthorizedConfig() async throws {
        let authorized = try Verifier(configAuthorizer: { _ in })
        do {
            _ = try await EnclaveConnection.router(
                attestor: Attestor(verifier: authorized.backend, fetch: { url in
                    XCTFail("fetched \(url) despite a verifier that can't discover a router")
                    throw TinfoilError.network("unreachable")
                }),
                transportMode: .ehbp,
                baseURL: nil,
                attestationRelay: nil,
                userCacheSecret: "secret",
                onVerificationResult: nil
            )
            XCTFail("expected the router to be refused")
        } catch TinfoilError.configurationError(let failure) {
            XCTAssertTrue(failure.message.contains("requires an explicit enclave"), failure.message)
        }
    }

    /// Go calls the Swift authorizer during verification with the document's
    /// config, and a rejection fails the document at the provenance layer
    /// with the authorizer's message.
    func testConfigAuthorizerRejects() throws {
        let seen = Seen()
        let verifier = try Verifier(
            embeddedReferences: .init(runtime: fixture.runtime, platform: fixture.platform),
            configAuthorizer: { endorsement in
                seen.add(endorsement)
                throw TinfoilError.configuration("config is not on the allow list")
            }
        )
        XCTAssertThrowsError(try verifier.backend.verify(document: fixture.document, nonce: fixture.nonce, repo: "")) { error in
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
        let verifier = try Verifier(
            embeddedReferences: .init(runtime: fixture.runtime, platform: fixture.platform),
            configAuthorizer: { seen.add($0) }
        )
        XCTAssertThrowsError(try verifier.backend.verify(document: fixture.document, nonce: fixture.nonce, repo: "")) { error in
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
        let verifier = try Verifier(
            embeddedReferences: .init(runtime: fixture.runtime, platform: fixture.platform),
            configAuthorizer: { seen.add($0) }
        )
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            _ = try? verifier.backend.verify(document: fixture.document, nonce: fixture.nonce, repo: "")
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
