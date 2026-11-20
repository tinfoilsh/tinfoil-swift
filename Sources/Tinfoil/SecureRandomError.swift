import Foundation

/// The system's secure random number generator failed, so the prompt-cache
/// secret that a router or gateway client generates for the process could
/// not be made. The client's initializer throws it as it is, outside
/// `TinfoilError`'s categories, since neither the configuration, the network
/// nor an attestation failed. No predictable secret is used in its place, and
/// the failure is not remembered: the next client that needs the secret tries
/// again. Passing a non-empty `userCacheSecret` needs no generation.
public struct SecureRandomError: Error, Equatable, Sendable, CustomStringConvertible {
    /// The status that `SecRandomCopyBytes` returned
    public let status: OSStatus

    public var description: String {
        "the system random number generator failed (OSStatus \(status))"
    }
}
