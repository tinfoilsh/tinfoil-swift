import Foundation
import Tinfoil

/// Default configuration constants for Tinfoil
public enum TinfoilConstants {
    /// Default GitHub repository for the inference proxy
    public static let defaultGithubRepo = "tinfoilsh/confidential-model-router"

    /// Base URL for Tinfoil's attestation bundle
    public static let attestationBaseURL = "https://atc.tinfoil.sh"

    /// Default URL for fetching attestation bundles
    public static let defaultAttestationBundleURL = "\(attestationBaseURL)/attestation"

    /// Stable legacy inference enclave. This endpoint does not forward the
    /// per-request enclave routing header used by generic EHBP proxies.
    public static let inferenceEnclaveURL = "https://inference.tinfoil.sh"

    /// Placeholder for unknown host values
    internal static let unknownHost = "unknown"

    /// Verifier implementation embedded by this SDK release
    public static let verifierName = "tinfoil-go"
    public static let verifierVersion = Tinfoil.ClientVersion
    internal static let developmentVerifierVersion = "devel"
    internal static let unknownVerifierValue = "unknown"

    /// Error domain for URL parsing errors
    internal static let urlHelpersErrorDomain = "sh.tinfoil.url-helpers"

    /// Error code for invalid URL
    internal static let invalidURLErrorCode = 1001
}
