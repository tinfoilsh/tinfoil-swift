import Foundation
import TinfoilVerifier

/// Errors that can occur during verification
public enum VerificationError: Error {
    case verificationFailed(String)
    case jsonDecodingFailed(String)
    case unknown(Error)
}

/// Measurement structure matching Go's attestation.Measurement
public struct Measurement: Codable {
    public let type: String
    public let registers: [String]
    
    private enum CodingKeys: String, CodingKey {
        case type
        case registers
    }
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
    public let enclaveHost: String?
    public let tlsPublicKey: String
    public let hpkePublicKey: String?
    public let digest: String
    public let codeMeasurement: Measurement?
    public let enclaveMeasurement: Measurement?
    public let hardwareMeasurement: HardwareMeasurementData?
    public let codeFingerprint: String
    public let enclaveFingerprint: String

    private enum CodingKeys: String, CodingKey {
        case enclaveHost = "enclave_host"
        case tlsPublicKey = "tls_public_key"
        case hpkePublicKey = "hpke_public_key"
        case digest
        case codeMeasurement = "code_measurement"
        case enclaveMeasurement = "enclave_measurement"
        case hardwareMeasurement = "hardware_measurement"
        case codeFingerprint = "code_fingerprint"
        case enclaveFingerprint = "enclave_fingerprint"
    }
}

/// A client for securely verifying code integrity through remote attestation
public class SecureClient {
    private let githubRepo: String
    private var enclaveURL: String?
    private let attestationBundleURL: String?
    private var groundTruth: GroundTruth?
    private var lastVerificationDocument: VerificationDocument?

    /// Initialize a secure client for direct enclave verification
    /// - Parameters:
    ///   - githubRepo: GitHub repository in the format "org/repo"
    ///   - enclaveURL: URL for the enclave attestation endpoint
    public init(
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        enclaveURL: String
    ) {
        self.githubRepo = githubRepo
        self.enclaveURL = enclaveURL
        self.attestationBundleURL = nil
    }

    /// Initialize a secure client for ATC-based verification (single-request flow)
    /// - Parameters:
    ///   - githubRepo: GitHub repository in the format "org/repo"
    ///   - attestationBundleURL: Base URL for fetching the attestation bundle. If nil, uses default ATC endpoint.
    public init(
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        attestationBundleURL: String? = nil
    ) {
        self.githubRepo = githubRepo
        self.enclaveURL = nil
        self.attestationBundleURL = attestationBundleURL ?? ""
    }

    /// Returns the verified enclave URL (available after successful verification)
    public func getEnclaveURL() -> String? {
        return enclaveURL
    }

    /// Returns the last verified ground truth
    public func getGroundTruth() -> GroundTruth? {
        return groundTruth
    }

    /// Returns the full verification document from the last verification attempt
    public func getVerificationDocument() -> VerificationDocument? {
        return lastVerificationDocument
    }

    /// Verifies the committed code and runtime binaries using remote attestation
    /// - Returns: The ground truth containing all verification results
    public func verify() async throws -> GroundTruth {
        var steps = VerificationDocument.Steps(
            fetchDigest: .pending(),
            verifyCode: .pending(),
            verifyEnclave: .pending(),
            compareMeasurements: .pending()
        )

        let jsonString: String

        do {
            var error: NSError?

            if let attestationBundleURL = attestationBundleURL {
                // ATC-based verification (single-request flow)
                jsonString = TinfoilVerifier.ClientVerifyFromATCURLJSON(attestationBundleURL, githubRepo, nil, &error)
            } else if let enclaveURL = enclaveURL {
                // Direct enclave verification
                let urlComponents = try URLHelpers.parseURL(enclaveURL)
                jsonString = TinfoilVerifier.ClientVerifyJSON(urlComponents.host, githubRepo, nil, &error)
            } else {
                throw VerificationError.verificationFailed("No enclave URL or ATC URL configured")
            }

            if let error = error {
                throw error
            }

            steps = VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .success(),
                verifyEnclave: .success(),
                compareMeasurements: .success()
            )
        } catch let error as NSError {
            let errorMessage = error.localizedDescription
            steps = Self.stepsFromError(errorMessage)
            buildFailureDocument(error: error, steps: steps)
            throw error
        } catch {
            buildFailureDocument(error: error, steps: steps)
            throw error
        }

        guard let jsonData = jsonString.data(using: String.Encoding.utf8) else {
            let verificationError = VerificationError.jsonDecodingFailed("Failed to convert JSON string to data")
            steps = VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .success(),
                verifyEnclave: .success(),
                compareMeasurements: .success(),
                otherError: .failed(verificationError.localizedDescription)
            )
            buildFailureDocument(error: verificationError, steps: steps)
            throw verificationError
        }

        let decoder = JSONDecoder()
        do {
            let groundTruth = try decoder.decode(GroundTruth.self, from: jsonData)
            self.groundTruth = groundTruth

            // Get enclave host from ground truth (for ATC flow) or existing URL
            let enclaveHost: String
            if let host = groundTruth.enclaveHost, !host.isEmpty {
                enclaveHost = host
                // Update enclaveURL for ATC flow so getEnclaveURL() returns the verified domain
                if self.enclaveURL == nil {
                    self.enclaveURL = "https://\(host)"
                }
            } else if let existingURL = enclaveURL, let urlComponents = try? URLHelpers.parseURL(existingURL) {
                enclaveHost = urlComponents.host
            } else {
                enclaveHost = TinfoilConstants.unknownHost
            }

            let codeMeasurement = AttestationMeasurement(
                type: groundTruth.codeMeasurement?.type ?? "",
                registers: groundTruth.codeMeasurement?.registers ?? []
            )

            let enclaveMeasurement = AttestationResponse(
                measurement: AttestationMeasurement(
                    type: groundTruth.enclaveMeasurement?.type ?? "",
                    registers: groundTruth.enclaveMeasurement?.registers ?? []
                ),
                tlsPublicKeyFingerprint: groundTruth.tlsPublicKey.isEmpty ? nil : groundTruth.tlsPublicKey,
                hpkePublicKey: groundTruth.hpkePublicKey
            )

            lastVerificationDocument = VerificationDocument(
                configRepo: githubRepo,
                enclaveHost: enclaveHost,
                releaseDigest: groundTruth.digest,
                codeMeasurement: codeMeasurement,
                enclaveMeasurement: enclaveMeasurement,
                tlsPublicKey: groundTruth.tlsPublicKey,
                hpkePublicKey: groundTruth.hpkePublicKey ?? "",
                hardwareMeasurement: groundTruth.hardwareMeasurement.map { hw in
                    HardwareMeasurement(
                        id: hw.id,
                        mrtd: hw.mrtd,
                        rtmr0: hw.rtmr0
                    )
                },
                codeFingerprint: groundTruth.codeFingerprint,
                enclaveFingerprint: groundTruth.enclaveFingerprint,
                selectedRouterEndpoint: enclaveHost,
                securityVerified: true,
                steps: steps
            )

            return groundTruth
        } catch {
            let decodingError = VerificationError.jsonDecodingFailed(error.localizedDescription)
            steps = VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .success(),
                verifyEnclave: .success(),
                compareMeasurements: .success(),
                otherError: .failed("Failed to decode verification result: \(error.localizedDescription)")
            )
            buildFailureDocument(error: decodingError, steps: steps)
            throw decodingError
        }
    }

    /// Maps error message prefixes to verification step states
    private static func stepsFromError(_ errorMessage: String) -> VerificationDocument.Steps {
        if errorMessage.starts(with: "fetchDigest:") || errorMessage.starts(with: "failed to fetch bundle:") {
            return VerificationDocument.Steps(
                fetchDigest: .failed(errorMessage),
                verifyCode: .pending(),
                verifyEnclave: .pending(),
                compareMeasurements: .pending()
            )
        } else if errorMessage.starts(with: "verifyCode:") {
            return VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .failed(errorMessage),
                verifyEnclave: .pending(),
                compareMeasurements: .pending()
            )
        } else if errorMessage.starts(with: "verifyEnclave:") {
            return VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .success(),
                verifyEnclave: .failed(errorMessage),
                compareMeasurements: .pending()
            )
        } else if errorMessage.starts(with: "verifyHardware:") ||
                  errorMessage.starts(with: "validateTLS:") ||
                  errorMessage.starts(with: "measurements:") {
            return VerificationDocument.Steps(
                fetchDigest: .success(),
                verifyCode: .success(),
                verifyEnclave: .success(),
                compareMeasurements: .failed(errorMessage)
            )
        } else {
            return VerificationDocument.Steps(
                fetchDigest: .pending(),
                verifyCode: .pending(),
                verifyEnclave: .pending(),
                compareMeasurements: .pending(),
                otherError: .failed(errorMessage)
            )
        }
    }

    /// Helper method to build a failure verification document
    private func buildFailureDocument(error: Error, steps: VerificationDocument.Steps) {
        let host: String
        if let enclaveURL = enclaveURL {
            host = (try? URLHelpers.parseURL(enclaveURL))?.host ?? enclaveURL
        } else {
            host = TinfoilConstants.unknownHost
        }

        lastVerificationDocument = VerificationDocument(
            configRepo: githubRepo,
            enclaveHost: host,
            releaseDigest: "",
            codeMeasurement: AttestationMeasurement(type: "", registers: []),
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
