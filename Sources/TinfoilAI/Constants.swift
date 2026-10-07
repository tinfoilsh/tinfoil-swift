import Foundation

/// Default configuration constants for Tinfoil
public enum TinfoilConstants {
    /// Default GitHub repository for the inference proxy
    public static let defaultGithubRepo = "tinfoilsh/confidential-model-router"

    /// Name this SDK reports in attestation requests and verification records
    public static let sdkName = "tinfoil-swift"

    /// Version of this SDK. The release workflow requires the release tag to be
    /// `v` followed by this value.
    public static let sdkVersion = "0.9.0-rc.1"

    /// Lists the routers a client tries when no enclave is configured
    internal static let routerListURL = URL(string: "https://atc.tinfoil.sh/routers")!

    /// Router used when no discovered router verifies
    internal static let fallbackEnclave = "inference.tinfoil.sh"

    /// Error domain for URL parsing errors
    internal static let urlHelpersErrorDomain = "sh.tinfoil.url-helpers"

    /// Error code for invalid URL
    internal static let invalidURLErrorCode = 1001

    /// X25519 public keys used by EHBP are always 32 bytes.
    internal static let hpkePublicKeyByteCount = 32
}
