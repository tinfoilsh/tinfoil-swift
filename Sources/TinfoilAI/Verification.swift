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
public enum VerificationError: LocalizedError {
    case verificationFailed(String)
    case jsonDecodingFailed(String)
    case notVerified
    case unknown(Error)

    public var errorDescription: String? {
        switch self {
        case .verificationFailed(let message), .jsonDecodingFailed(let message):
            return message
        case .notVerified:
            return "The enclave has not been verified"
        case .unknown(let error):
            return error.localizedDescription
        }
    }
}

/// Measurement structure matching Go's measurement.Measurement
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
    private let pinnedMeasurement: AttestationMeasurement?
    private let vmShape: VMShape?
    private var discoveredEnclaveURL: String?
    private var groundTruth: GroundTruth?
    private var lastVerificationDocument: VerificationDocument?
    private var goClient: ClientSecureClient?

    /// Initialize a secure client for v3 verification.
    /// - Parameters:
    ///   - githubRepo: GitHub repository in the format "org/repo"
    ///   - enclaveURL: Explicit enclave origin, or nil for default router discovery.
    ///     Custom repositories require an explicit enclave.
    public convenience init(
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        enclaveURL: String? = nil
    ) {
        self.init(
            githubRepo: githubRepo,
            configuredEnclaveURL: enclaveURL
        )
    }

    /// Initialize a secure client that verifies the enclave against a
    /// caller-supplied measurement instead of the code provenance carried in
    /// its attestation document. Only the code-provenance check is skipped: the
    /// platform endorsements, their freshness proof, the CPU quote chain, and
    /// channel binding are still verified. The measurement's provenance must be
    /// established out of band; the verification document reports the skipped
    /// steps as skipped.
    /// - Parameters:
    ///   - enclaveURL: URL for the enclave attestation endpoint
    ///   - pinnedMeasurement: Expected enclave code measurement
    ///   - vmShape: The VM shape the pinned code was built for. Required for
    ///     TDX enclaves, ignored for SEV-SNP.
    public convenience init(
        enclaveURL: String,
        pinnedMeasurement: AttestationMeasurement,
        vmShape: VMShape? = nil
    ) {
        self.init(
            githubRepo: TinfoilConstants.pinnedNoRepo,
            configuredEnclaveURL: enclaveURL,
            pinnedMeasurement: pinnedMeasurement,
            vmShape: vmShape
        )
    }

    private init(
        githubRepo: String,
        configuredEnclaveURL: String?,
        pinnedMeasurement: AttestationMeasurement? = nil,
        vmShape: VMShape? = nil
    ) {
        self.githubRepo = githubRepo
        self.configuredEnclaveURL = configuredEnclaveURL
        self.pinnedMeasurement = pinnedMeasurement
        self.vmShape = vmShape
    }

    /// Creates the Go verifier for `host`, in pinned-measurement mode when a
    /// measurement was supplied. The pinned Go constructor takes the
    /// measurements as JSON because gomobile cannot bind the struct types.
    internal func makeGoClient(host: String?) throws -> ClientSecureClient {
        if pinnedMeasurement == nil, let host {
            guard let client = ClientNewSecureClient(host, githubRepo) else {
                throw VerificationError.verificationFailed("Failed to create secure verifier for \(host)")
            }
            return client
        }

        guard let pinnedMeasurement else {
            guard githubRepo == TinfoilConstants.defaultGithubRepo else {
                throw VerificationError.verificationFailed("A custom githubRepo requires enclaveURL")
            }
            var error: NSError?
            guard let client = ClientNewDefaultClient(&error) else {
                if let error { throw error }
                throw VerificationError.verificationFailed("Failed to discover a secure enclave")
            }
            return client
        }

        guard let host else {
            throw VerificationError.verificationFailed("pinnedMeasurement requires enclaveURL")
        }

        let encoder = JSONEncoder()
        let measurementJSON = String(decoding: try encoder.encode(pinnedMeasurement), as: UTF8.self)
        let shapeJSON = try vmShape.map { String(decoding: try encoder.encode($0), as: UTF8.self) } ?? ""

        var error: NSError?
        guard let client = ClientNewPinnedSecureClientJSON(host, measurementJSON, shapeJSON, &error) else {
            if let error { throw error }
            throw VerificationError.verificationFailed("Failed to create pinned secure verifier for \(host)")
        }
        return client
    }

    internal static func verifyIfNeeded(_ client: ClientSecureClient) throws {
        // Discovery may already verify a router, but its fallback is unverified.
        if client.groundTruth() == nil {
            _ = try client.verify()
        }
    }

    /// The verified enclave URL (available after successful verification)
    public var verifiedEnclaveURL: String? { discoveredEnclaveURL }

    /// The last verified ground truth
    public var verifiedGroundTruth: GroundTruth? { groundTruth }

    /// The full verification document from the last verification attempt
    public var verificationDocument: VerificationDocument? { lastVerificationDocument }

    /// Verifies the committed code and runtime binaries using remote attestation
    /// - Returns: The ground truth containing all verification results
    public func verify() async throws -> GroundTruth {
        do {
            let configuredOrigin = try configuredEnclaveURL.map { try URLHelpers.parseEnclaveURL($0) }
            let client = try makeGoClient(host: configuredOrigin?.authority)
            try Self.verifyIfNeeded(client)

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
            let discoveredURL = decodedGroundTruth.enclaveHost.flatMap { $0.isEmpty ? nil : "https://\($0)" }
            if let configuredOrigin {
                guard let discoveredURL,
                      URLHelpers.origin(from: discoveredURL) == URLHelpers.origin(from: configuredOrigin.url) else {
                    throw VerificationError.verificationFailed(
                        "Verified enclave does not match configured origin \(configuredOrigin.url)"
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
                !document.verifier.version.isEmpty,
                !document.codeFingerprint.isEmpty,
                document.codeFingerprint == document.enclaveFingerprint
            else {
                throw VerificationError.jsonDecodingFailed("Verification document is missing required provenance")
            }
            guard
                document.configRepo == githubRepo,
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

            self.discoveredEnclaveURL = configuredOrigin?.url ?? discoveredURL

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

        let configuredHost = try configuredEnclaveURL.map { try URLHelpers.parseEnclaveURL($0).authority }
        guard let host = configuredHost ?? groundTruth.enclaveHost else {
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
        pinnedMeasurement: Bool = false
    ) -> VerificationDocument.Steps {
        // v3 carries reference values in the document; there is no release
        // lookup. Pinned mode also skips the code-provenance step.
        let completedCode: VerificationStepState = pinnedMeasurement ? .skipped() : .success()
        if errorMessage.starts(with: "fetching attestation document:") ||
           errorMessage.starts(with: "envelope:") ||
           errorMessage.starts(with: "generating nonce:") {
            return VerificationDocument.Steps(
                fetchDigest: .skipped(),
                verifyCode: pinnedMeasurement ? .skipped() : .pending(),
                verifyEnclave: .pending(),
                compareMeasurements: .pending(),
                otherError: .failed(errorMessage)
            )
        } else if errorMessage.starts(with: "reference values:") {
            let codeFailed = errorMessage.starts(with: "reference values: verifying code")
            let platformFailed = errorMessage.starts(with: "reference values: verifying platform")
            let codeStep: VerificationStepState = pinnedMeasurement ? .skipped()
                : codeFailed ? .failed(errorMessage)
                : platformFailed ? .success() : .pending()
            return VerificationDocument.Steps(
                fetchDigest: .skipped(),
                verifyCode: codeStep,
                verifyEnclave: .pending(),
                compareMeasurements: .pending(),
                otherError: codeFailed && !pinnedMeasurement ? nil : .failed(errorMessage)
            )
        } else if errorMessage.starts(with: "measurements:") {
            return VerificationDocument.Steps(
                fetchDigest: .skipped(),
                verifyCode: completedCode,
                verifyEnclave: .success(),
                compareMeasurements: .failed(errorMessage)
            )
        } else if errorMessage.starts(with: "cpu evidence:") {
            return VerificationDocument.Steps(
                fetchDigest: .skipped(),
                verifyCode: completedCode,
                verifyEnclave: .failed(errorMessage),
                compareMeasurements: .pending()
            )
        } else if errorMessage.starts(with: "binding:") {
            return VerificationDocument.Steps(
                fetchDigest: .skipped(),
                verifyCode: completedCode,
                verifyEnclave: .success(),
                compareMeasurements: .success(),
                verifyCertificate: .failed(errorMessage)
            )
        } else {
            // Without a recognized step prefix nothing is known to have run, but
            // a pinned client never performs the provenance steps at all.
            let provenance: VerificationStepState = pinnedMeasurement ? .skipped() : .pending()
            return VerificationDocument.Steps(
                fetchDigest: .skipped(),
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
            host = (try? URLHelpers.parseEnclaveURL(url))?.authority ?? url
        } else {
            host = TinfoilConstants.unknownHost
        }

        lastVerificationDocument = Self.makeFailureDocument(
            configRepo: githubRepo,
            enclaveHost: host,
            pinnedMeasurement: pinnedMeasurement,
            steps: steps
        )
    }

    internal static func makeFailureDocument(
        configRepo: String,
        enclaveHost: String,
        pinnedMeasurement: AttestationMeasurement?,
        steps: VerificationDocument.Steps
    ) -> VerificationDocument {
        let failureSteps = VerificationDocument.Steps(
            fetchDigest: .skipped(),
            verifyCode: pinnedMeasurement == nil ? steps.verifyCode : .skipped(),
            verifyEnclave: steps.verifyEnclave,
            compareMeasurements: steps.compareMeasurements,
            verifyCertificate: steps.verifyCertificate,
            createTransport: steps.createTransport,
            verifyHPKEKey: steps.verifyHPKEKey,
            otherError: steps.otherError
        )

        return VerificationDocument(
            configRepo: configRepo,
            enclaveHost: enclaveHost,
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
            selectedRouterEndpoint: enclaveHost,
            securityVerified: false,
            steps: failureSteps
        )
    }
}
