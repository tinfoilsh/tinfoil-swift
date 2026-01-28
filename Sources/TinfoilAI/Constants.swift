import Foundation

/// Default configuration constants for Tinfoil
public enum TinfoilConstants {
    /// Default GitHub repository for the inference proxy
    public static let defaultGithubRepo = "tinfoilsh/confidential-model-router"

    /// ATC (Attestation and Trust Center) base URL
    public static let atcBaseURL = "https://atc.tinfoil.sh"

    /// ATC API URL for fetching available routers
    public static let atcRoutersURL = "\(atcBaseURL)/routers"

    /// ATC API URL for fetching attestation bundles
    public static let atcAttestationURL = "\(atcBaseURL)/attestation"
}