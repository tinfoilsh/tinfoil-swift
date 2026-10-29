import Foundation

/// Errors that can occur when using the Tinfoil clients, in three
/// categories: configuration, network and attestation. Each case carries a
/// struct of details, as `DecodingError` does, so a detail can be added
/// without breaking callers. Errors from the inference API itself keep their
/// own types.
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

/// The layer of the verifier that rejected an attestation document. More
/// layers may be added, so match the ones you handle and tolerate any other.
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
