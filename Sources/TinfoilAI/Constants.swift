import Foundation

/// Default configuration constants for Tinfoil
public enum TinfoilConstants {
    /// Default GitHub repository for the inference proxy
    public static let defaultGithubRepo = "tinfoilsh/confidential-model-router"

    /// Base URL for Tinfoil's attestation service
    public static let atcBaseURL = "https://atc.tinfoil.sh"

    /// Default URL for fetching attestation bundles
    public static let atcAttestationURL = "\(atcBaseURL)/attestation"

    /// Placeholder for unknown host values
    internal static let unknownHost = "unknown"

    /// Error domain for URL parsing errors
    internal static let urlHelpersErrorDomain = "sh.tinfoil.url-helpers"

    /// Error code for invalid URL
    internal static let invalidURLErrorCode = 1001
}