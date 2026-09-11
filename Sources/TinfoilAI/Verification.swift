import Foundation
import Tinfoil

/// Response from an attested HTTP request
public struct SecureResponse: Sendable {
    /// HTTP status code
    public let statusCode: Int

    /// Response body data
    public let body: Data

    /// Response body as a UTF-8 string
    public var bodyString: String? {
        String(data: body, encoding: .utf8)
    }
}

/// Errors that can occur during verification
public enum VerificationError: Error {
    case verificationFailed(String)
    case jsonDecodingFailed(String)
    case notVerified
    case unknown(Error)
}

/// Measurement structure matching Go's attestation.Measurement
public struct Measurement: Codable {
    public let type: String
    public let registers: [String]
}

/// Hardware measurement structure for TDX platforms
public struct HardwareMeasurementData: Codable {
    public let id: String
    public let mrtd: String
    public let rtmr0: String

    private enum CodingKeys: String, CodingKey {
        case id = "ID"
        case mrtd = "MRTD"
        case rtmr0 = "RTMR0"
    }
}

/// Ground truth structure matching Go's client.GroundTruth
public struct GroundTruth: Codable {
    public let configRepo: String?
    public let enclaveHost: String?
    public let releaseTag: String?
    public let tlsPublicKey: String
    public let hpkePublicKey: String?
    public let digest: String
    public let codeMeasurement: Measurement?
    public let enclaveMeasurement: Measurement?
    public let hardwareMeasurement: HardwareMeasurementData?
    public let codeFingerprint: String
    public let enclaveFingerprint: String
    public let verifier: SoftwareIdentity?
    public let verifiedAt: String?

    private enum CodingKeys: String, CodingKey {
        case configRepo = "config_repo"
        case enclaveHost = "enclave_host"
        case releaseTag = "release_tag"
        case tlsPublicKey = "tls_public_key"
        case hpkePublicKey = "hpke_public_key"
        case digest
        case codeMeasurement = "code_measurement"
        case enclaveMeasurement = "enclave_measurement"
        case hardwareMeasurement = "hardware_measurement"
        case codeFingerprint = "code_fingerprint"
        case enclaveFingerprint = "enclave_fingerprint"
        case verifier
        case verifiedAt = "verified_at"
    }
}

/// A client for securely verifying code integrity through remote attestation
public class SecureClient {
    private let githubRepo: String
    private let configuredEnclaveURL: String?
    private let attestationBundleURL: String?
    private let pinnedMeasurement: AttestationMeasurement?
    private let hardwareMeasurements: [HardwareMeasurement]
    private var discoveredEnclaveURL: String?
    private var groundTruth: GroundTruth?
    private var lastVerificationDocument: VerificationDocument?
    private var goClient: ClientSecureClient?

    /// Initialize a secure client for direct enclave verification
    /// - Parameters:
    ///   - githubRepo: GitHub repository in the format "org/repo"
    ///   - enclaveURL: URL for the enclave attestation endpoint
    public convenience init(
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        enclaveURL: String
    ) {
        self.init(
            githubRepo: githubRepo,
            configuredEnclaveURL: enclaveURL,
            attestationBundleURL: nil
        )
    }

    /// Initialize a secure client that requests a bundle for one specific
    /// enclave. This binds the destination, certificate, and HPKE key to the
    /// same verified domain while retaining the single-request bundle flow.
    public convenience init(
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        enclaveURL: String,
        attestationBundleURL: String
    ) {
        self.init(
            githubRepo: githubRepo,
            configuredEnclaveURL: enclaveURL,
            attestationBundleURL: attestationBundleURL
        )
    }

    /// Initialize a secure client that fetches an attestation bundle for verification
    /// - Parameters:
    ///   - githubRepo: GitHub repository in the format "org/repo"
    ///   - attestationBundleURL: URL for fetching the attestation bundle. If nil, uses default Tinfoil endpoint.
    public convenience init(
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        attestationBundleURL: String? = nil
    ) {
        self.init(
            githubRepo: githubRepo,
            configuredEnclaveURL: nil,
            attestationBundleURL: attestationBundleURL
        )
    }

    /// Initialize a secure client that verifies the enclave against a
    /// caller-supplied measurement instead of the latest signed release of a
    /// config repo. The GitHub release lookup and Sigstore code verification
    /// are skipped, so the measurement's provenance must be established out of
    /// band; the verification document reports those steps as skipped.
    /// - Parameters:
    ///   - enclaveURL: URL for the enclave attestation endpoint
    ///   - pinnedMeasurement: Expected enclave code measurement
    ///   - hardwareMeasurements: Optional TDX platform measurements that replace
    ///     the Sigstore-published values. When empty, they are still fetched from
    ///     Sigstore for TDX enclaves.
    public convenience init(
        enclaveURL: String,
        pinnedMeasurement: AttestationMeasurement,
        hardwareMeasurements: [HardwareMeasurement] = []
    ) {
        self.init(
            githubRepo: TinfoilConstants.pinnedNoRepo,
            configuredEnclaveURL: enclaveURL,
            attestationBundleURL: nil,
            pinnedMeasurement: pinnedMeasurement,
            hardwareMeasurements: hardwareMeasurements
        )
    }

    private init(
        githubRepo: String,
        configuredEnclaveURL: String?,
        attestationBundleURL: String?,
        pinnedMeasurement: AttestationMeasurement? = nil,
        hardwareMeasurements: [HardwareMeasurement] = []
    ) {
        self.githubRepo = githubRepo
        self.configuredEnclaveURL = configuredEnclaveURL
        self.attestationBundleURL = attestationBundleURL
        self.pinnedMeasurement = pinnedMeasurement
        self.hardwareMeasurements = hardwareMeasurements
    }

    /// Creates the Go verifier for `host`, in pinned-measurement mode when a
    /// measurement was supplied. The pinned Go constructor takes the
    /// measurements as JSON because gomobile cannot bind the struct types.
    private func makeGoClient(host: String) throws -> ClientSecureClient {
        guard let pinnedMeasurement else {
            guard let client = ClientNewSecureClient(host, githubRepo) else {
                throw VerificationError.verificationFailed("Failed to create secure verifier for \(host)")
            }
            return client
        }

        let encoder = JSONEncoder()
        let measurementJSON = String(decoding: try encoder.encode(pinnedMeasurement), as: UTF8.self)
        let hardwareJSON = hardwareMeasurements.isEmpty
            ? ""
            : String(decoding: try encoder.encode(hardwareMeasurements), as: UTF8.self)

        var error: NSError?
        guard let client = ClientNewPinnedSecureClientJSON(host, measurementJSON, hardwareJSON, &error) else {
            if let error { throw error }
            throw VerificationError.verificationFailed("Failed to create pinned secure verifier for \(host)")
        }
        return client
    }

    /// The verified enclave URL (available after successful verification)
    public var verifiedEnclaveURL: String? { discoveredEnclaveURL ?? configuredEnclaveURL }

    /// The last verified ground truth
    public var verifiedGroundTruth: GroundTruth? { groundTruth }

    /// The full verification document from the last verification attempt
    public var verificationDocument: VerificationDocument? { lastVerificationDocument }

    /// Verifies the committed code and runtime binaries using remote attestation
    /// - Returns: The ground truth containing all verification results
    public func verify() async throws -> GroundTruth {
        do {
            let host: String
            if let configuredEnclaveURL = configuredEnclaveURL {
                host = try URLHelpers.parseURL(configuredEnclaveURL).host
            } else {
                host = ""
            }

            let client = try makeGoClient(host: host)
            if let attestationBundleURL {
                client.setAttestationBundleURL(attestationBundleURL)
            } else if configuredEnclaveURL == nil {
                client.setAttestationBundleURL(TinfoilConstants.attestationBaseURL)
            }

            _ = try client.verify()

            var jsonError: NSError?
            let groundTruthJSON = client.groundTruthJSON(&jsonError)
            if let jsonError { throw jsonError }
            let verificationDocumentJSON = client.verificationDocumentJSON(&jsonError)
            if let jsonError { throw jsonError }

            guard
                let groundTruthData = groundTruthJSON.data(using: String.Encoding.utf8),
                let verificationDocumentData = verificationDocumentJSON.data(using: String.Encoding.utf8)
            else {
                throw VerificationError.jsonDecodingFailed("Failed to convert verification JSON to data")
            }

            let decoder = JSONDecoder()
            let decodedGroundTruth = try decoder.decode(GroundTruth.self, from: groundTruthData)
            var document = try decoder.decode(VerificationDocument.self, from: verificationDocumentData)
            if configuredEnclaveURL != nil {
                guard decodedGroundTruth.enclaveHost?.caseInsensitiveCompare(host) == .orderedSame else {
                    throw VerificationError.verificationFailed(
                        "Attestation bundle domain does not match configured enclave \(host)"
                    )
                }
            }
            if document.verifier.version == TinfoilConstants.developmentVerifierVersion ||
               document.verifier.version == TinfoilConstants.unknownVerifierValue {
                document = document.replacingVerifier(
                    SoftwareIdentity(
                        name: document.verifier.name,
                        version: TinfoilConstants.verifierVersion
                    )
                )
            }
            guard
                document.schemaVersion == 1,
                document.securityVerified,
                document.allStepsSucceeded,
                !(document.verifiedAt?.isEmpty ?? true),
                !document.verifier.name.isEmpty,
                !document.verifier.version.isEmpty
            else {
                throw VerificationError.jsonDecodingFailed("Verification document is missing required provenance")
            }
            guard
                document.configRepo == decodedGroundTruth.configRepo,
                document.enclaveHost == decodedGroundTruth.enclaveHost,
                document.releaseTag == decodedGroundTruth.releaseTag,
                document.releaseDigest == decodedGroundTruth.digest,
                document.tlsPublicKey == decodedGroundTruth.tlsPublicKey,
                document.hpkePublicKey == (decodedGroundTruth.hpkePublicKey ?? ""),
                document.codeFingerprint == decodedGroundTruth.codeFingerprint,
                document.enclaveFingerprint == decodedGroundTruth.enclaveFingerprint
            else {
                throw VerificationError.jsonDecodingFailed("Verification document does not match ground truth")
            }

            let groundTruth = GroundTruth(
                configRepo: decodedGroundTruth.configRepo,
                enclaveHost: decodedGroundTruth.enclaveHost,
                releaseTag: decodedGroundTruth.releaseTag,
                tlsPublicKey: decodedGroundTruth.tlsPublicKey,
                hpkePublicKey: decodedGroundTruth.hpkePublicKey,
                digest: decodedGroundTruth.digest,
                codeMeasurement: decodedGroundTruth.codeMeasurement,
                enclaveMeasurement: decodedGroundTruth.enclaveMeasurement,
                hardwareMeasurement: decodedGroundTruth.hardwareMeasurement,
                codeFingerprint: decodedGroundTruth.codeFingerprint,
                enclaveFingerprint: decodedGroundTruth.enclaveFingerprint,
                verifier: document.verifier,
                verifiedAt: document.verifiedAt
            )

            self.groundTruth = groundTruth
            self.lastVerificationDocument = document
            self.goClient = client

            if let host = groundTruth.enclaveHost, !host.isEmpty {
                self.discoveredEnclaveURL = "https://\(host)"
            }

            return groundTruth
        } catch let error as VerificationError {
            clearVerifiedState()
            buildFailureDocument(error: error, steps: .init(otherError: .failed(error.localizedDescription)))
            throw error
        } catch let error as DecodingError {
            clearVerifiedState()
            let decodingError = VerificationError.jsonDecodingFailed(error.localizedDescription)
            buildFailureDocument(error: decodingError, steps: .init(otherError: .failed(decodingError.localizedDescription)))
            throw decodingError
        } catch let error as NSError {
            clearVerifiedState()
            let steps = Self.stepsFromError(
                error.localizedDescription,
                usesBundle: attestationBundleURL != nil || configuredEnclaveURL == nil,
                pinnedMeasurement: pinnedMeasurement != nil
            )
            buildFailureDocument(error: error, steps: steps)
            throw error
        } catch {
            clearVerifiedState()
            buildFailureDocument(error: error, steps: .init(otherError: .failed(error.localizedDescription)))
            throw error
        }
    }

    // MARK: - Attested HTTP Requests

    /// Returns the Go SecureClient, creating it if needed from verified enclave info
    private func getGoClient() throws -> ClientSecureClient {
        if let existing = goClient {
            return existing
        }

        guard let groundTruth = groundTruth else {
            throw VerificationError.notVerified
        }

        guard let host = groundTruth.enclaveHost ?? (configuredEnclaveURL.flatMap { try? URLHelpers.parseURL($0).host }) else {
            throw VerificationError.verificationFailed("No enclave host available")
        }

        let client = try makeGoClient(host: host)
        goClient = client
        return client
    }

    /// Makes an attested HTTP GET request to the verified enclave
    /// - Parameters:
    ///   - url: The URL to request (absolute or relative path)
    ///   - headers: Optional HTTP headers
    /// - Returns: The response with status code and body
    public func get(url: String, headers: [String: String]? = nil) async throws -> SecureResponse {
        let client = try getGoClient()
        let headersJSON = try encodeHeaders(headers)

        let response = try client.secureGet(url, headersJSON: headersJSON)

        return SecureResponse(
            statusCode: response.statusCode,
            body: response.body ?? Data()
        )
    }

    /// Makes an attested HTTP POST request to the verified enclave
    /// - Parameters:
    ///   - url: The URL to request (absolute or relative path)
    ///   - headers: Optional HTTP headers
    ///   - body: Optional request body
    /// - Returns: The response with status code and body
    public func post(url: String, headers: [String: String]? = nil, body: Data? = nil) async throws -> SecureResponse {
        let client = try getGoClient()
        let headersJSON = try encodeHeaders(headers)

        let response = try client.securePost(url, headersJSON: headersJSON, body: body)

        return SecureResponse(
            statusCode: response.statusCode,
            body: response.body ?? Data()
        )
    }

    private func encodeHeaders(_ headers: [String: String]?) throws -> String {
        guard let headers = headers, !headers.isEmpty else {
            return ""
        }
        let data = try JSONSerialization.data(withJSONObject: headers)
        return String(data: data, encoding: .utf8) ?? ""
    }

    /// Maps error message prefixes to verification step states
    internal static func stepsFromError(
        _ errorMessage: String,
        usesBundle: Bool = false,
        pinnedMeasurement: Bool = false
    ) -> VerificationDocument.Steps {
        // A pinned measurement skips the release lookup and code verification
        // entirely, so those steps are reported as skipped rather than succeeded.
        let completedFetch: VerificationStepState = usesBundle || pinnedMeasurement ? .skipped() : .success()
        let completedCode: VerificationStepState = pinnedMeasurement ? .skipped() : .success()
        if usesBundle && (errorMessage.starts(with: "fetchBundle:") || errorMessage.starts(with: "failed to fetch bundle:")) {
            return VerificationDocument.Steps(
                fetchDigest: .skipped(),
                verifyCode: .pending(),
                verifyEnclave: .pending(),
                compareMeasurements: .pending(),
                otherError: .failed(errorMessage)
            )
        } else if errorMessage.starts(with: "fetchDigest:") ||
           errorMessage.starts(with: "fetchBundle:") ||
           errorMessage.starts(with: "failed to fetch bundle:") {
            return VerificationDocument.Steps(
                fetchDigest: .failed(errorMessage),
                verifyCode: .pending(),
                verifyEnclave: .pending(),
                compareMeasurements: .pending()
            )
        } else if errorMessage.starts(with: "verifyCode:") {
            return VerificationDocument.Steps(
                fetchDigest: completedFetch,
                verifyCode: .failed(errorMessage),
                verifyEnclave: .pending(),
                compareMeasurements: .pending()
            )
        } else if errorMessage.starts(with: "verifyEnclave:") {
            return VerificationDocument.Steps(
                fetchDigest: completedFetch,
                verifyCode: completedCode,
                verifyEnclave: .failed(errorMessage),
                compareMeasurements: .pending()
            )
        } else if errorMessage.starts(with: "validateTLS:") ||
                  errorMessage.starts(with: "verifyCertificate:") {
            return VerificationDocument.Steps(
                fetchDigest: completedFetch,
                verifyCode: completedCode,
                verifyEnclave: .success(),
                compareMeasurements: usesBundle ? .success() : .pending(),
                verifyCertificate: .failed(errorMessage)
            )
        } else if errorMessage.starts(with: "verifyHardware:") ||
                  errorMessage.starts(with: "measurements:") {
            return VerificationDocument.Steps(
                fetchDigest: completedFetch,
                verifyCode: completedCode,
                verifyEnclave: .success(),
                compareMeasurements: .failed(errorMessage)
            )
        } else {
            // Without a recognized step prefix nothing is known to have run, but
            // a pinned client never performs the provenance steps at all.
            let provenance: VerificationStepState = pinnedMeasurement ? .skipped() : .pending()
            return VerificationDocument.Steps(
                fetchDigest: provenance,
                verifyCode: provenance,
                verifyEnclave: .pending(),
                compareMeasurements: .pending(),
                otherError: .failed(errorMessage)
            )
        }
    }

    private func clearVerifiedState() {
        groundTruth = nil
        goClient = nil
        discoveredEnclaveURL = nil
    }

    /// Helper method to build a failure verification document
    private func buildFailureDocument(error: Error, steps: VerificationDocument.Steps) {
        let host: String
        if let url = discoveredEnclaveURL ?? configuredEnclaveURL {
            host = (try? URLHelpers.parseURL(url))?.host ?? url
        } else {
            host = TinfoilConstants.unknownHost
        }

        lastVerificationDocument = VerificationDocument(
            configRepo: githubRepo,
            enclaveHost: host,
            releaseDigest: pinnedMeasurement == nil ? "" : TinfoilConstants.pinnedNoDigest,
            codeMeasurement: pinnedMeasurement ?? AttestationMeasurement(type: "", registers: []),
            enclaveMeasurement: AttestationResponse(
                measurement: AttestationMeasurement(type: "", registers: [])
            ),
            tlsPublicKey: "",
            hpkePublicKey: "",
            hardwareMeasurement: nil,
            codeFingerprint: "",
            enclaveFingerprint: "",
            selectedRouterEndpoint: host,
            securityVerified: false,
            steps: steps
        )
    }
}
