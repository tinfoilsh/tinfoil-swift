import Foundation
@_exported import OpenAI
import EHBP

/// Main entry point for the Tinfoil client library.
/// Provides the same API as OpenAI client with EHBP encryption for secure enclave communication.
public class TinfoilAI: OpenAICompatibleClient {
    /// This SDK's version, as tinfoil-go's `Version()` reports its own
    public static let version = TinfoilConstants.sdkVersion

    public let openAI: OpenAI

    private init(client: OpenAI) {
        self.openAI = client
    }

    /// Creates a TinfoilAI client on Tinfoil's default route, a router picked
    /// and verified as `RouterHTTPClient` does, as tinfoil-go's `NewClient`
    /// does. Every request body is sealed to the verified enclave with EHBP.
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from TINFOIL_API_KEY environment variable
    ///   - parsingOptions: Parsing options for handling different providers.
    ///   - customHeaders: Additional request headers to forward verbatim on
    ///     every outbound request (merged over the headers synthesized by
    ///     `tinfoilEvents`; caller values win on conflict). Use for arbitrary
    ///     router / proxy pass-through headers.
    ///   - tinfoilEvents: Optional set of Tinfoil-specific progress events
    ///     to opt into. Each selected event contributes one comma-separated
    ///     value on the `X-Tinfoil-Events` request header so the router
    ///     emits `<tinfoil-event>...</tinfoil-event>` markers inline with
    ///     the assistant text. Strict OpenAI SDKs render the markers as
    ///     text; callers parse and strip them before display.
    /// - Returns: A TinfoilAI client configured for secure communication (use like OpenAI client)
    ///
    /// Servers holding many end users' conversations should set the
    /// `user_cache_secret` field per request (e.g. via `ChatQuery.extraBody`);
    /// a non-empty per-request string wins over the client's secret.
    public static func create(
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        tinfoilEvents: Set<TinfoilEvent> = []
    ) async throws -> TinfoilAI {
        // Checked before discovery, so a missing key costs no network I/O.
        let staticApiKey = try OpenAI.apiKey(apiKey, provider: apiKeyProvider)
        let router = try await RouterHTTPClient()
        return TinfoilAI(client: try OpenAI.sealed(
            apiKey: staticApiKey,
            apiKeyProvider: apiKeyProvider,
            connection: router.connection,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            tinfoilEvents: tinfoilEvents
        ))
    }

    /// Internal initializer that seals to a fixed enclave key, for tests.
    /// `userCacheSecret` is the already-resolved prompt-cache scoping secret
    /// (see `UserCacheSecret.resolve`). `expiresAt` is when the key's
    /// attestation stops authorizing new requests.
    internal convenience init(
        apiKey: String?,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        baseURL: String,
        enclaveURL: String,
        hpkePublicKeyHex: String?,
        expiresAt: Date = .distantFuture,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        tinfoilEvents: Set<TinfoilEvent> = [],
        userCacheSecret: String = "",
        refreshEndpoint: EHBPVerifiedState.Refresh? = nil
    ) throws {
        let verifiedState = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(
                enclaveURL: enclaveURL,
                publicKey: try EHBPVerifiedEndpoint.publicKey(hex: hpkePublicKeyHex),
                expiresAt: expiresAt
            ),
            refresh: refreshEndpoint
        )
        self.init(client: try OpenAI.sealed(
            apiKey: apiKey,
            apiKeyProvider: apiKeyProvider,
            baseURL: baseURL,
            session: EHBPURLSession(baseURL: baseURL, verifiedState: verifiedState, userCacheSecret: userCacheSecret),
            streamingFactory: EHBPURLSessionFactory(baseURL: baseURL, verifiedState: verifiedState, userCacheSecret: userCacheSecret),
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            tinfoilEvents: tinfoilEvents
        ))
    }
}

/// Errors that can occur when using the Tinfoil client, in the three
/// categories tinfoil-go reports. Each case carries a struct of details, as
/// `DecodingError` does, so a detail can be added without breaking callers.
/// Errors from the inference API itself keep their own types.
public enum TinfoilError: Error, Equatable {
    /// The caller's arguments or client configuration are invalid, as is a
    /// request the client refuses to send, such as one leaving the verified
    /// enclave. Retrying will not help.
    case configurationError(Configuration)
    /// The client could not fetch the attestation material it needed.
    case networkError(Network)
    /// The enclave's evidence, the policy or the channel binding was rejected,
    /// including by an `onEnclaveVerified` callback.
    case attestationError(Attestation)

    /// Details of a configuration error
    public struct Configuration: Equatable, Sendable {
        public let message: String
    }

    /// Details of a network error
    public struct Network: Equatable, Sendable {
        public let message: String
        /// Set when the request failed in transit, as when offline or timed
        /// out. Neither this nor `status` is set when the SDK refused the
        /// response itself, as for one too large or a redirect off HTTPS.
        public let urlError: URLError?
        /// Set when the server answered with an HTTP error status
        public let status: Int?
    }

    /// Details of an attestation error
    public struct Attestation: Equatable, Sendable {
        public let message: String
        /// The layer of the verifier that rejected the attestation document,
        /// when it did
        public let layer: VerificationLayer?
    }

    /// The error's message, whatever its category
    public var message: String {
        switch self {
        case .configurationError(let details):
            return details.message
        case .networkError(let details):
            return details.message
        case .attestationError(let details):
            return details.message
        }
    }
}

/// Shorthand the SDK throws with, each building its case's details: for
/// example, `.attestation("rejected")` is
/// `.attestationError(Attestation(message: "rejected", layer: nil))`.
extension TinfoilError {
    static func configuration(_ message: String) -> TinfoilError {
        .configurationError(Configuration(message: message))
    }

    static func network(_ message: String, urlError: URLError? = nil, status: Int? = nil) -> TinfoilError {
        .networkError(Network(message: message, urlError: urlError, status: status))
    }

    static func attestation(_ message: String, layer: VerificationLayer? = nil) -> TinfoilError {
        .attestationError(Attestation(message: message, layer: layer))
    }
}

/// The verification layer that rejected an attestation document, as
/// tinfoil-go's `verify.Layer` names it. More layers may be added, so match
/// the ones you handle and tolerate any other.
public struct VerificationLayer: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    /// A document that can't be parsed or isn't bound to the request
    public static let envelope = VerificationLayer(rawValue: "envelope")
    /// Reference values that fail to authenticate
    public static let provenance = VerificationLayer(rawValue: "provenance")
    /// Hardware evidence that isn't authentic
    public static let quote = VerificationLayer(rawValue: "quote")
    /// Authentic evidence that doesn't satisfy the policy
    public static let policy = VerificationLayer(rawValue: "policy")

    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public var description: String { rawValue }
}

/// Gives `localizedDescription` each error's message, rather than Foundation's
/// generic "The operation couldn't be completed" with an enum case number.
extension TinfoilError: LocalizedError {
    public var errorDescription: String? {
        message
    }
}
