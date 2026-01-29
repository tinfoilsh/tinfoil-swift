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
    private let enclaveURL: String
    private var groundTruth: GroundTruth?
    private var lastVerificationDocument: VerificationDocument?

    /// Initialize a secure client with required configuration
    /// - Parameters:
    ///   - githubRepo: GitHub repository in the format "org/repo"
    ///   - enclaveURL: URL for the enclave attestation endpoint
    public init(
        githubRepo: String = TinfoilConstants.defaultGithubRepo,
        enclaveURL: String
    ) {
        self.githubRepo = githubRepo
        self.enclaveURL = enclaveURL
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

        let urlComponents: (url: URL, host: String, scheme: String, port: Int?)
        do {
            urlComponents = try URLHelpers.parseURL(enclaveURL)
        } catch {
            let verificationError = VerificationError.verificationFailed("Invalid enclave URL: \(error.localizedDescription)")
            buildFailureDocument(error: verificationError, steps: steps)
            throw verificationError
        }

        let jsonString: String
        do {
            var error: NSError?
            jsonString = TinfoilVerifier.ClientVerifyJSON(urlComponents.host, githubRepo, nil, &error)

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

            // Check error prefix to determine which step failed
            if errorMessage.starts(with: "fetchDigest:") {
                steps = VerificationDocument.Steps(
                    fetchDigest: .failed(errorMessage),
                    verifyCode: .pending(),
                    verifyEnclave: .pending(),
                    compareMeasurements: .pending()
                )
            } else if errorMessage.starts(with: "verifyCode:") {
                steps = VerificationDocument.Steps(
                    fetchDigest: .success(),
                    verifyCode: .failed(errorMessage),
                    verifyEnclave: .pending(),
                    compareMeasurements: .pending()
                )
            } else if errorMessage.starts(with: "verifyEnclave:") {
                steps = VerificationDocument.Steps(
                    fetchDigest: .success(),
                    verifyCode: .success(),
                    verifyEnclave: .failed(errorMessage),
                    compareMeasurements: .pending()
                )
            } else if errorMessage.starts(with: "verifyHardware:") {
                steps = VerificationDocument.Steps(
                    fetchDigest: .success(),
                    verifyCode: .success(),
                    verifyEnclave: .success(),
                    compareMeasurements: .failed(errorMessage)
                )
            } else if errorMessage.starts(with: "validateTLS:") || errorMessage.starts(with: "measurements:") {
                steps = VerificationDocument.Steps(
                    fetchDigest: .success(),
                    verifyCode: .success(),
                    verifyEnclave: .success(),
                    compareMeasurements: .failed(errorMessage)
                )
            } else {
                steps = VerificationDocument.Steps(
                    fetchDigest: .pending(),
                    verifyCode: .pending(),
                    verifyEnclave: .pending(),
                    compareMeasurements: .pending(),
                    otherError: .failed(errorMessage)
                )
            }

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
                enclaveHost: urlComponents.host,
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
                selectedRouterEndpoint: urlComponents.host,
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

    /// Helper method to build a failure verification document
    private func buildFailureDocument(error: Error, steps: VerificationDocument.Steps) {
        let host = (try? URLHelpers.parseURL(enclaveURL))?.host ?? enclaveURL

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
