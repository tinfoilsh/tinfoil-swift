import Foundation
@testable import TinfoilAI

/// Stands in for the Go verifier. A document is "<verdict>:<nonce hex>"; the
/// stand-in refuses one whose nonce is not the one it was given, so the tests
/// also prove the attestor carries a single nonce through each attempt.
final class FakeVerifier: AttestationVerifier, @unchecked Sendable {
    private let lock = NSLock()
    private var issued: UInt8 = 0
    private var _repos: [String] = []

    var repos: [String] {
        lock.lock()
        defer { lock.unlock() }
        return _repos
    }

    func newNonce() -> Data {
        lock.lock()
        defer { lock.unlock() }
        issued += 1
        return Data(repeating: issued, count: 32)
    }

    func attestationURL(host: String, relay: String?, nonce: Data) throws -> URL {
        var url = "https://\(relay ?? host)/.well-known/tinfoil-attestation?nonce=\(nonce.hexString)"
        if relay != nil {
            url += "&enclave=\(host)"
        }
        return URL(string: url)!
    }

    func verify(document: Data, nonce: Data, repo: String, enclaveHost: String) throws -> Verification {
        lock.lock()
        _repos.append(repo)
        lock.unlock()
        let parts = String(decoding: document, as: UTF8.self).split(separator: ":").map(String.init)
        guard parts.count == 2, parts[1] == nonce.hexString else {
            throw TinfoilError.attestationError("document is not bound to the nonce")
        }
        switch parts[0] {
        case "ok":
            return .stub(host: enclaveHost)
        case "config":
            throw TinfoilError.invalidConfiguration("bad repo")
        default:
            throw TinfoilError.attestationError("rejected")
        }
    }
}

/// Serves each fetch from a script and records the URLs asked for.
final class FakeNetwork: @unchecked Sendable {
    private let lock = NSLock()
    private var _urls: [URL] = []
    private let respond: (URL, Int) throws -> String

    /// respond receives the URL and how many times its host has been fetched
    /// before.
    init(respond: @escaping (URL, Int) throws -> String) {
        self.respond = respond
    }

    var urls: [URL] {
        lock.lock()
        defer { lock.unlock() }
        return _urls
    }

    func fetch(_ url: URL) throws -> Data {
        lock.lock()
        let previous = _urls.filter { $0.host == url.host }.count
        _urls.append(url)
        lock.unlock()
        return Data(try respond(url, previous).utf8)
    }

    /// A document with the given verdict, bound to the nonce in url.
    static func document(_ verdict: String, for url: URL) -> String {
        let nonce = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems?.first { $0.name == "nonce" }?.value ?? ""
        return "\(verdict):\(nonce)"
    }
}

extension Verification {
    static func stub(host: String) -> Verification {
        Verification(
            enclaveHost: host,
            configRepo: TinfoilConstants.defaultGithubRepo,
            codeDigest: "abc123",
            codeTag: nil,
            codeMeasurement: nil,
            enclaveMeasurement: nil,
            tlsPublicKeyFingerprint: "deadbeef",
            hpkePublicKey: "cafebabe",
            cryptoMaterial: [],
            freshnessExpiresAt: Date().addingTimeInterval(3600),
            verifiedAt: Date(),
            verifier: SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion)
        )
    }
}
