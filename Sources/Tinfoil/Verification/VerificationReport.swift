import Foundation

/// A record of one verification: the steps that the verifier ran and the
/// facts that it established. The same type describes both outcomes:
///
/// - On success, a client returns the report. Its `verifiedFacts` are set,
///   and no step failed.
/// - On failure, the client throws `TinfoilError.attestationError`, whose
///   `verificationError` carries the report when the verifier rejected the
///   document. In that report one step failed, `partialFacts` are set and
///   `verifiedFacts` are not.
///
/// A report authorizes nothing: the only output that authorizes an action is
/// the endorsed key material in `verifiedFacts`. A report decoded from JSON is
/// a record of a verification, not a verification; only a client's own
/// verifier produces the reports that it binds channels to.
public struct VerificationReport: Sendable, Equatable, Codable {
    /// One step for each layer of the verifier, in layer order: today
    /// `envelope`, `provenance`, `quote` and `policy`. Every step is always
    /// present. More layers may be added.
    public let steps: [Step]
    /// What the document proved: set if and only if no step failed
    public let verifiedFacts: VerifiedFacts?
    /// What the verifier established before a step failed: set if and only
    /// if a step failed
    public let partialFacts: PartialFacts?
    /// The verifier's identity and the appraisal instant
    public let metadata: VerificationMetadata
}

/// One step of a verification: the checks of one layer of the verifier
public struct Step: Sendable, Equatable, Codable {
    /// The layer that the step covers
    public let layer: VerificationLayer
    /// Whether the step's checks ran and passed. Only the verifier sets a
    /// status: show a step as passed only when this says so.
    public let status: StepStatus
    /// For a failed step, the message of the verifier's error; for a skipped
    /// step, the reason that it was skipped; otherwise empty. Messages are
    /// diagnostic.
    public let message: String
}

/// The outcome of one step of a verification. More statuses may be added, so
/// match the ones that you handle and tolerate any other.
public struct StepStatus: RawRepresentable, Hashable, Sendable, Codable, CustomStringConvertible {
    /// Every check of the step's layer ran and passed
    public static let passed = StepStatus(rawValue: "passed")
    /// A check of the step's layer failed. At most one step fails: the one
    /// whose layer is the error's.
    public static let failed = StepStatus(rawValue: "failed")
    /// The layer does not apply to the document or to the verifier's
    /// configuration. It is not a failure.
    public static let skipped = StepStatus(rawValue: "skipped")
    /// The step's checks did not all run, because verification stopped at
    /// an earlier failure. A step that precedes the failed one can be not run
    /// too, since checks don't always run in layer order.
    public static let notRun = StepStatus(rawValue: "not_run")

    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public var description: String { rawValue }
}

/// What a verification established before a step failed, in two groups.
/// Each fact is set only once the step that establishes it passed.
public struct PartialFacts: Sendable, Equatable, Codable {
    /// Facts from authenticated reference values, set once the `provenance`
    /// step passed
    public let expected: ExpectedFacts?
    /// Facts from the document and its hardware evidence, set once the
    /// `envelope` step passed
    public let measured: MeasuredFacts?
}

/// The reference values that the verifier authenticated before a step
/// failed. A measurement mismatch shows `measurement` against
/// `MeasuredFacts.cpu`, register by register.
public struct ExpectedFacts: Sendable, Equatable, Codable {
    /// The selected config repository
    public let configRepo: String
    /// The authenticated release artifact
    public let artifact: ArtifactVerification
    /// The config, for a config-based verification
    public let config: ConfigVerification?
    /// The platform endorsements artifact, for a config-based verification
    public let platform: ArtifactVerification?
    /// The registers that the release fixes, in the layout of the platform
    /// that the document's CPU evidence declares, with an empty register for
    /// one that the release leaves to the platform. The values are
    /// authenticated; the platform that selects their layout is
    /// authenticated only once the `quote` step passed.
    public let codeMeasurement: VerifiedFacts.Measurement?
    /// The full set of registers that the quote had to attest: the code
    /// measurement, the caller's register pins, and the registers that the
    /// endorsed platform supplies. Set only once the `policy` step resolved
    /// them, even if a later check of that step failed.
    public let measurement: VerifiedFacts.Measurement?
}

/// What the document and its hardware evidence showed before a step failed.
/// The key fingerprints are only the document's claim, never verified: the
/// keys are bound to the enclave only when the `policy` step passes, which
/// it did not in a failed report. Present them as unverified, and never bind
/// a channel to them.
public struct MeasuredFacts: Sendable, Equatable, Codable {
    /// The hardware evidence, set only once the `quote` step passed
    public let cpu: CPUEvidence?
    /// The lowercase hex SHA-256 of the TLS key's DER `SubjectPublicKeyInfo`
    /// that the document endorses, or empty if it endorses none. Unverified.
    public let tlsPublicKeyFingerprint: String
    /// The lowercase hex SHA-256 of the HPKE key that the document endorses,
    /// or empty if it endorses none. Unverified, and never the key itself.
    public let hpkePublicKeyFingerprint: String
}

/// The authenticated hardware evidence of a CPU
public struct CPUEvidence: Sendable, Equatable, Codable {
    /// Every register that the hardware measured, in its platform's native
    /// layout
    public let measurement: VerifiedFacts.Measurement
}

/// The TinfoilGo verifier's rejection of an attestation document. The SDK
/// never throws it by itself: a client throws `TinfoilError.attestationError`,
/// whose `verificationError` is this error when the verifier rejected the
/// document, so that a caller can show the failed attempt. Choose what to do
/// from the `TinfoilError` category, not from this error's layer or report.
public struct VerificationError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The layer of the verifier that rejected the document
    public let layer: VerificationLayer
    /// The verifier's message, led by the layer, as in "quote: <detail>"
    public let message: String
    /// The verification's report, in which the step of `layer` failed
    public let report: VerificationReport

    public var description: String {
        "verification error: \(message)"
    }
}

extension VerificationReport {
    /// The verification result schema that this SDK decodes
    static let supportedSchemaVersion = 2

    /// When the verified facts expire, or the distant past for a report
    /// without them, which then never admits a request
    var freshnessExpiresAt: Date {
        verifiedFacts?.freshnessExpiresAt ?? .distantPast
    }

    /// The verified facts of a report that passed. Every report that the
    /// SDK's verifier returns has them; one that doesn't fails closed.
    func passedFacts() throws -> VerifiedFacts {
        guard let verifiedFacts else {
            throw TinfoilError.attestation("verification passed without verified facts")
        }
        return verifiedFacts
    }

    /// Decodes the result JSON of the TinfoilGo verifier, which it returns
    /// both for a document that it accepted and for one that it rejected.
    /// Returns the report of an accepted document, and throws
    /// `TinfoilError.attestationError` for a rejected one, with the
    /// verifier's error and report as its `verificationError`.
    ///
    /// - Parameter verificationPrefix: The prefix that leads the message of
    ///   a verifier's rejection
    static func decodeResult(_ payload: String, verificationPrefix: String) throws -> VerificationReport {
        let data = Data(payload.utf8)
        let decoder = JSONDecoder()
        // Read the version alone first, so that a payload in another schema is
        // reported as such rather than as a missing field.
        let version: SchemaVersion
        do {
            version = try decoder.decode(SchemaVersion.self, from: data)
        } catch {
            throw TinfoilError.attestation("unreadable verification result: \(error.localizedDescription)")
        }
        guard version.schemaVersion == supportedSchemaVersion else {
            throw TinfoilError.attestation(
                "unsupported verification schema version \(version.schemaVersion); this SDK reads version \(supportedSchemaVersion)"
            )
        }
        let decoded: ResultPayload
        do {
            decoded = try decoder.decode(ResultPayload.self, from: data)
        } catch {
            throw TinfoilError.attestation("unreadable verification result: \(error.localizedDescription)")
        }
        let report = try decoded.report.report()

        guard let rejection = decoded.error else {
            // An accepted document must carry what it proved and nothing that
            // only a failure has, or the result is not one the SDK can trust.
            guard report.verifiedFacts != nil, report.partialFacts == nil,
                  !report.steps.contains(where: { $0.status == .failed }) else {
                throw TinfoilError.attestation("verification result has no error but did not pass every step")
            }
            return report
        }
        guard report.verifiedFacts == nil else {
            throw TinfoilError.attestation("verification result has an error but carries verified facts")
        }
        let layer = VerificationLayer(rawValue: rejection.layer)
        let message = rejection.message.hasPrefix(verificationPrefix)
            ? String(rejection.message.dropFirst(verificationPrefix.count))
            : rejection.message
        throw TinfoilError.attestation(
            message,
            layer: layer,
            verificationError: VerificationError(layer: layer, message: message, report: report)
        )
    }

    private struct SchemaVersion: Decodable {
        let schemaVersion: Int

        private enum CodingKeys: String, CodingKey {
            case schemaVersion = "schema_version"
        }
    }

    // The payload as the TinfoilGo framework declares it, as resultJSON in
    // its source's mobile/verification.go; a change there needs a matching
    // change here.

    private struct ResultPayload: Decodable {
        let report: ReportPayload
        let error: ErrorPayload?
    }

    private struct ErrorPayload: Decodable {
        let layer: String
        let message: String
    }

    private struct ReportPayload: Decodable {
        let steps: [StepPayload]
        let verifiedFacts: VerifiedFactsPayload?
        let partialFacts: PartialFactsPayload?
        let metadata: MetadataPayload

        private enum CodingKeys: String, CodingKey {
            case steps, metadata
            case verifiedFacts = "verified_facts"
            case partialFacts = "partial_facts"
        }

        func report() throws -> VerificationReport {
            VerificationReport(
                steps: steps.map {
                    Step(layer: VerificationLayer(rawValue: $0.layer), status: StepStatus(rawValue: $0.status), message: $0.message ?? "")
                },
                verifiedFacts: try verifiedFacts?.facts(),
                partialFacts: try partialFacts?.facts(),
                metadata: VerificationMetadata(
                    verifier: SoftwareIdentity(name: TinfoilConstants.sdkName, version: TinfoilConstants.sdkVersion),
                    verifiedAt: try parseDate(metadata.verifiedAt, field: "metadata.verified_at")
                )
            )
        }
    }

    private struct StepPayload: Decodable {
        let layer: String
        let status: String
        let message: String?
    }

    private struct MetadataPayload: Decodable {
        let verifiedAt: String

        private enum CodingKeys: String, CodingKey {
            case verifiedAt = "verified_at"
        }
    }

    private struct PartialFactsPayload: Decodable {
        let expected: ExpectedFactsPayload?
        let measured: MeasuredFactsPayload?

        func facts() throws -> PartialFacts {
            PartialFacts(expected: try expected?.facts(), measured: measured?.facts())
        }
    }

    private struct ExpectedFactsPayload: Decodable {
        let configRepo: String
        let artifact: ArtifactPayload
        let config: ConfigPayload?
        let platform: ArtifactPayload?
        let codeMeasurement: VerifiedFacts.Measurement?
        let measurement: VerifiedFacts.Measurement?

        private enum CodingKeys: String, CodingKey {
            case artifact, config, platform, measurement
            case configRepo = "config_repo"
            case codeMeasurement = "code_measurement"
        }

        func facts() throws -> ExpectedFacts {
            ExpectedFacts(
                configRepo: configRepo,
                artifact: try artifact.verification(of: "partial_facts.expected.artifact"),
                config: try config?.verification(of: "partial_facts.expected.config"),
                platform: try platform?.verification(of: "partial_facts.expected.platform"),
                codeMeasurement: codeMeasurement,
                measurement: measurement
            )
        }
    }

    private struct MeasuredFactsPayload: Decodable {
        let cpuMeasurement: VerifiedFacts.Measurement?
        let tlsPublicKeyFP: String?
        let hpkePublicKeyFP: String?

        private enum CodingKeys: String, CodingKey {
            case cpuMeasurement = "cpu_measurement"
            case tlsPublicKeyFP = "tls_public_key_fp"
            case hpkePublicKeyFP = "hpke_public_key_fp"
        }

        func facts() -> MeasuredFacts {
            MeasuredFacts(
                cpu: cpuMeasurement.map { CPUEvidence(measurement: $0) },
                tlsPublicKeyFingerprint: tlsPublicKeyFP ?? "",
                hpkePublicKeyFingerprint: hpkePublicKeyFP ?? ""
            )
        }
    }

    private struct VerifiedFactsPayload: Decodable {
        let configRepo: String
        let codeDigest: String
        let codeTag: String?
        let codeMeasurement: VerifiedFacts.Measurement?
        let enclaveMeasurement: VerifiedFacts.Measurement?
        let config: ConfigPayload?
        let runtime: ArtifactPayload?
        let platform: ArtifactPayload?
        let tlsPublicKeyFP: String
        let hpkePublicKey: String?
        let cryptoMaterial: [VerifiedFacts.CryptoMaterial]
        let freshnessExpiresAt: String

        private enum CodingKeys: String, CodingKey {
            case configRepo = "config_repo"
            case codeDigest = "code_digest"
            case codeTag = "code_tag"
            case codeMeasurement = "code_measurement"
            case enclaveMeasurement = "enclave_measurement"
            case config, runtime, platform
            case tlsPublicKeyFP = "tls_public_key_fp"
            case hpkePublicKey = "hpke_public_key"
            case cryptoMaterial = "crypto_material"
            case freshnessExpiresAt = "freshness_expires_at"
        }

        func facts() throws -> VerifiedFacts {
            VerifiedFacts(
                configRepo: configRepo,
                codeDigest: codeDigest,
                codeTag: codeTag ?? "",
                codeMeasurement: codeMeasurement,
                enclaveMeasurement: enclaveMeasurement,
                config: try config?.verification(of: "verified_facts.config"),
                runtime: try runtime?.verification(of: "verified_facts.runtime"),
                platform: try platform?.verification(of: "verified_facts.platform"),
                tlsPublicKeyFingerprint: tlsPublicKeyFP,
                hpkePublicKey: hpkePublicKey ?? "",
                cryptoMaterial: cryptoMaterial,
                freshnessExpiresAt: try parseDate(freshnessExpiresAt, field: "verified_facts.freshness_expires_at")
            )
        }
    }

    private struct ConfigPayload: Decodable {
        let source: String
        let name: String?
        let digest: String
        let reference: String?
        let signingKeyHint: String?
        let approvalTime: String?
        let registryID: String?
        let signatureTime: String?

        private enum CodingKeys: String, CodingKey {
            case source, name, digest, reference
            case signingKeyHint = "signing_key_hint"
            case approvalTime = "approval_time"
            case registryID = "registry_id"
            case signatureTime = "signature_time"
        }

        /// - Parameter field: The config's member, which errors name
        func verification(of field: String) throws -> ConfigVerification {
            ConfigVerification(
                source: ReferenceSource(rawValue: source),
                name: name ?? "",
                digest: digest,
                reference: reference ?? "",
                signingKeyHint: signingKeyHint ?? "",
                approvalTime: try approvalTime.map { try parseDate($0, field: "\(field).approval_time") },
                registryID: registryID ?? "",
                signatureTime: try signatureTime.map { try parseDate($0, field: "\(field).signature_time") }
            )
        }
    }

    private struct ArtifactPayload: Decodable {
        let source: String
        let repo: String?
        let tag: String?
        let digest: String
        let name: String?
        let commit: String?
        let approvalTime: String?

        private enum CodingKeys: String, CodingKey {
            case source, repo, tag, digest, name, commit
            case approvalTime = "approval_time"
        }

        /// - Parameter field: The artifact's member, which errors name
        func verification(of field: String) throws -> ArtifactVerification {
            ArtifactVerification(
                source: ReferenceSource(rawValue: source),
                repo: repo ?? "",
                tag: tag ?? "",
                digest: digest,
                name: name ?? "",
                commit: commit ?? "",
                approvalTime: try approvalTime.map { try parseDate($0, field: "\(field).approval_time") }
            )
        }
    }

    /// The framework writes RFC 3339 and drops a zero fractional part, so
    /// both forms arrive. Each style is tried in turn because older Foundation
    /// releases parse only the form that a style names.
    private static func parseDate(_ value: String, field: String) throws -> Date {
        let styles = [
            Date.ISO8601FormatStyle(includingFractionalSeconds: true),
            Date.ISO8601FormatStyle(),
        ]
        for style in styles {
            if let date = try? style.parse(value) {
                return date
            }
        }
        throw TinfoilError.attestation("verification result has an invalid \(field): \(value)")
    }
}

extension TinfoilError {
    /// Classifies an error from the TinfoilGo verifier that came without a
    /// report, such as a usage error. It crosses the framework boundary as a
    /// message alone, led by its category's prefix, which is dropped here
    /// because the case carries the category. A verification error's message
    /// then names the layer that rejected the document, as in
    /// "quote: <detail>"; the layer is kept in the message and also lifted
    /// out. A message with neither prefix is treated as a rejected
    /// attestation.
    static func fromVerifier(
        _ error: Error,
        usagePrefix: String,
        verificationPrefix: String
    ) -> TinfoilError {
        let message = error.localizedDescription
        if message.hasPrefix(usagePrefix) {
            return .configuration(String(message.dropFirst(usagePrefix.count)))
        }
        if message.hasPrefix(verificationPrefix) {
            let rejection = String(message.dropFirst(verificationPrefix.count))
            return .attestation(rejection, layer: layer(leading: rejection))
        }
        return .attestation(message)
    }

    /// The layer that a verification error's message leads with, as in
    /// "quote: <detail>". Layer names are single lowercase words, so a message
    /// whose text before ": " is anything else names no layer.
    private static func layer(leading message: String) -> VerificationLayer? {
        guard let separator = message.range(of: ": ") else {
            return nil
        }
        let name = message[..<separator.lowerBound]
        guard !name.isEmpty, name.allSatisfy({ $0.isASCII && $0.isLowercase }) else {
            return nil
        }
        return VerificationLayer(rawValue: String(name))
    }
}
