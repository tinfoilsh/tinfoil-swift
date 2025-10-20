import Foundation

/// Default configuration constants for Tinfoil
public enum TinfoilConstants {
    /// Default GitHub repository for the inference proxy
    public static let defaultGithubRepo = "tinfoilsh/confidential-model-router"

    /// ATC (Attestation and Trust Center) API URL for fetching available routers
    public static let atcAPIURL = "https://atc.tinfoil.sh/routers"
}