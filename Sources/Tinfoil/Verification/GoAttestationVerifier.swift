import Foundation
import TinfoilGo

/// The TinfoilGo framework's verifier. It makes every trust decision; this
/// only translates types and errors across the framework boundary.
final class GoAttestationVerifier: AttestationVerifier, @unchecked Sendable {
    // MobileVerifier wraps an immutable policy that is safe to use from
    // several threads at once.
    private let verifier: MobileVerifier

    // The framework holds the bridge only through a reference that it
    // tracks; keeping it here ties its lifetime to the verifier's.
    private let configAuthorizer: ConfigAuthorizerBridge?

    /// - Parameters:
    ///   - optionsJSON: The framework's options; empty for the defaults
    ///   - configAuthorizer: Decides which configs are authorized, in place of
    ///     their endorsements
    init(optionsJSON: String = "", configAuthorizer: ConfigAuthorizerBridge? = nil) throws {
        var error: NSError?
        let verifier: MobileVerifier?
        if let configAuthorizer {
            verifier = MobileNewVerifierWithConfigAuthorizer(optionsJSON, configAuthorizer, &error)
        } else {
            verifier = MobileNewVerifier(optionsJSON, &error)
        }
        if let error {
            throw Self.classify(error)
        }
        guard let verifier else {
            throw TinfoilError.configuration("TinfoilGo returned no verifier")
        }
        self.verifier = verifier
        self.configAuthorizer = configAuthorizer
    }

    var callerAuthorizesConfig: Bool {
        verifier.callerAuthorizesConfig()
    }

    func checkRepoVerifiability(_ repo: String) throws {
        do {
            try verifier.checkRepoVerifiability(repo)
        } catch {
            throw Self.classify(error)
        }
    }

    func newNonce() -> Data {
        // The framework never returns nil here. If it did, the empty nonce
        // would be refused by attestationURL, so the attempt still fails
        // closed.
        MobileNewNonce() ?? Data()
    }

    func attestationURL(host: String, relay: String?, nonce: Data) throws -> URL {
        var error: NSError?
        let url = MobileAttestationURL(host, relay ?? "", nonce, &error)
        if let error {
            throw Self.classify(error)
        }
        guard let parsed = URL(string: url) else {
            throw TinfoilError.configuration("TinfoilGo returned an invalid attestation URL: \(url)")
        }
        return parsed
    }

    func verify(document: Data, nonce: Data, repo: String) throws -> Verification {
        var error: NSError?
        let payload = verifier.verify(document, nonce: nonce, repo: repo, error: &error)
        if let error {
            throw Self.classify(error)
        }
        return try Verification(payload: payload)
    }

    private static func classify(_ error: Error) -> TinfoilError {
        TinfoilError.fromVerifier(
            error,
            usagePrefix: MobileUsageErrorPrefix,
            verificationPrefix: MobileVerificationErrorPrefix
        )
    }
}
