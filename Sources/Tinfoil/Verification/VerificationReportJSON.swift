import Foundation

// The JSON form of a verification report that every Tinfoil SDK writes, so
// that a consumer, such as a verification user interface or a proxy that
// relays results, reads the report of every SDK in the same way. `JSONEncoder`
// writes it from a `VerificationReport` or from any of the facts that it
// holds:
//
//     {
//       "schema_version": 1,
//       "steps": [
//         {"layer": "envelope", "status": "passed"},
//         {"layer": "provenance", "status": "passed"},
//         {"layer": "quote", "status": "failed", "message": "<detail>"},
//         {"layer": "policy", "status": "not_run"}
//       ],
//       "verified_facts": { ...on success only... },
//       "partial_facts": { ...on a rejection only... },
//       "metadata": {
//         "verified_at": "<RFC 3339, UTC>",
//         "verifier": {"name": "tinfoil-swift", "version": "<version>"},
//         "host": "<the host that the client contacted>"
//       }
//     }
//
// Member names are snake_case, hex is lowercase and times are RFC 3339 in UTC,
// written with `Z`. A fact that the verifier did not establish is omitted, and
// no member is ever null or "", but a fact that was established and holds
// nothing stays, as in "measured": {}. A measurement names its platform and
// its registers: {"platform": "sev-snp", "launch"} or {"platform": "tdx",
// "mrtd", "rtmr0", ..., "rtmr3"}, without a register that the release leaves
// to the platform. The channel keys appear only in
// verified_facts.crypto_material. metadata.host, in a report that a client
// produced, is the host that the client contacted, which is not attested.
//
// The types conform to `Encodable` only. Nothing in the SDK reads the form
// back into a report or into verified facts, since anyone can write verified
// facts in JSON: the form is for display and transport, and it authorizes
// nothing.

extension VerificationReport: Encodable {
    /// The `schema_version` of the report's JSON form. Adding a member keeps
    /// the version; removing or renaming one, or changing what one means,
    /// bumps it.
    public static let jsonSchemaVersion = 1

    private enum CodingKeys: String, CodingKey {
        case steps, metadata
        case schemaVersion = "schema_version"
        case verifiedFacts = "verified_facts"
        case partialFacts = "partial_facts"
    }

    /// Writes the report in the JSON form that every Tinfoil SDK writes. The
    /// JSON authorizes nothing: never bind a channel to a key that was read
    /// from it.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(Self.jsonSchemaVersion, forKey: .schemaVersion)
        try container.encode(steps, forKey: .steps)
        try container.encodeIfPresent(verifiedFacts, forKey: .verifiedFacts)
        try container.encodeIfPresent(partialFacts, forKey: .partialFacts)
        try container.encode(metadata, forKey: .metadata)
    }
}

extension Step: Encodable {
    private enum CodingKeys: String, CodingKey {
        case layer, status, message
    }

    /// Writes `{"layer", "status", "message"}`, without a message that is
    /// empty
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(layer.rawValue, forKey: .layer)
        try container.encode(status.rawValue, forKey: .status)
        try container.encodeIfNotEmpty(message, forKey: .message)
    }
}

extension StepStatus: Encodable {
    /// Writes the status's raw value, such as "not_run"
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

extension VerificationMetadata: Encodable {
    private enum CodingKeys: String, CodingKey {
        case verifier, host
        case verifiedAt = "verified_at"
    }

    /// Writes `{"verified_at", "verifier", "host"}`, without a host that is
    /// nil or empty
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(ReportTime.format(verifiedAt), forKey: .verifiedAt)
        if !verifier.name.isEmpty, !verifier.version.isEmpty {
            try container.encode(verifier, forKey: .verifier)
        }
        try container.encodeIfNotEmpty(host ?? "", forKey: .host)
    }
}

extension ReferenceSource: Encodable {
    /// Writes the source's raw value, such as "endorsement"
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

extension ConfigVerification: Encodable {
    private enum CodingKeys: String, CodingKey {
        case source, name, digest, reference
        case signingKeyHint = "signing_key_hint"
        case approvalTime = "approval_time"
        case registryID = "registry_id"
        case signatureTime = "signature_time"
    }

    /// Writes the config record of the JSON form, without the members that
    /// are empty or nil
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(source, forKey: .source)
        try container.encodeIfNotEmpty(name, forKey: .name)
        try container.encode(digest, forKey: .digest)
        try container.encodeIfNotEmpty(reference, forKey: .reference)
        try container.encodeIfNotEmpty(signingKeyHint, forKey: .signingKeyHint)
        try container.encodeIfPresent(approvalTime.map(ReportTime.format), forKey: .approvalTime)
        try container.encodeIfNotEmpty(registryID, forKey: .registryID)
        try container.encodeIfPresent(signatureTime.map(ReportTime.format), forKey: .signatureTime)
    }
}

extension ArtifactVerification: Encodable {
    private enum CodingKeys: String, CodingKey {
        case source, repo, tag, digest, name, commit
        case approvalTime = "approval_time"
    }

    /// Writes the artifact record of the JSON form, without the members that
    /// are empty or nil
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(source, forKey: .source)
        try container.encodeIfNotEmpty(repo, forKey: .repo)
        try container.encodeIfNotEmpty(tag, forKey: .tag)
        try container.encode(digest, forKey: .digest)
        try container.encodeIfNotEmpty(name, forKey: .name)
        try container.encodeIfNotEmpty(commit, forKey: .commit)
        try container.encodeIfPresent(approvalTime.map(ReportTime.format), forKey: .approvalTime)
    }
}

extension VerifiedFacts: Encodable {
    private enum CodingKeys: String, CodingKey {
        case config, runtime, platform
        case configRepo = "config_repo"
        case codeDigest = "code_digest"
        case codeTag = "code_tag"
        case codeMeasurement = "code_measurement"
        case enclaveMeasurement = "enclave_measurement"
        case cryptoMaterial = "crypto_material"
        case freshnessExpiresAt = "freshness_expires_at"
    }

    /// Writes the verified_facts object of the JSON form. The TLS and HPKE
    /// keys appear only in `crypto_material`, and a code measurement that
    /// constrains no register is omitted.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(configRepo, forKey: .configRepo)
        try container.encode(codeDigest, forKey: .codeDigest)
        try container.encodeIfNotEmpty(codeTag, forKey: .codeTag)
        try container.encodeIfPresent(codeMeasurement?.constrained, forKey: .codeMeasurement)
        try container.encodeIfPresent(enclaveMeasurement, forKey: .enclaveMeasurement)
        try container.encodeIfPresent(config, forKey: .config)
        try container.encodeIfPresent(runtime, forKey: .runtime)
        try container.encodeIfPresent(platform, forKey: .platform)
        try container.encode(cryptoMaterial, forKey: .cryptoMaterial)
        try container.encode(ReportTime.format(freshnessExpiresAt), forKey: .freshnessExpiresAt)
    }
}

extension VerifiedFacts.Measurement: Encodable {
    /// Writes `{"platform", <register>: <hex>, ...}`: "sev-snp" with "launch",
    /// or "tdx" with "mrtd" and "rtmr0" to "rtmr3", without an empty register.
    /// A measurement of a type that the SDK doesn't know, or with the wrong
    /// number of registers, can't be written and throws
    /// `EncodingError.invalidValue`.
    public func encode(to encoder: Encoder) throws {
        guard let layout = Layout.of(type: type), layout.registers.count == registers.count else {
            throw EncodingError.invalidValue(self, EncodingError.Context(
                codingPath: encoder.codingPath,
                debugDescription: "a measurement of type \(type) with \(registers.count) registers has no JSON form"
            ))
        }
        var container = encoder.container(keyedBy: JSONKey.self)
        try container.encode(layout.platform, forKey: JSONKey("platform"))
        for (name, value) in zip(layout.registers, registers) where !value.isEmpty {
            try container.encode(value.lowercased(), forKey: JSONKey(name))
        }
    }

    /// The measurement, or nil when it constrains no register, which the JSON
    /// form omits
    var constrained: Self? {
        registers.contains { !$0.isEmpty } ? self : nil
    }

    /// How a measurement type's registers are named in the JSON form
    struct Layout {
        let type: String
        let platform: String
        /// The registers' names, in the order of `Measurement.registers`
        let registers: [String]

        static let all = [
            Layout(type: "https://tinfoil.sh/predicate/sev-snp-guest/v2", platform: "sev-snp", registers: ["launch"]),
            Layout(
                type: "https://tinfoil.sh/predicate/tdx-guest/v2",
                platform: "tdx",
                registers: ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
            ),
        ]

        static func of(type: String) -> Layout? {
            all.first { $0.type == type }
        }

        static func of(platform: String) -> Layout? {
            all.first { $0.platform == platform }
        }
    }
}

extension PartialFacts: Encodable {
    private enum CodingKeys: String, CodingKey {
        case expected, measured
    }

    /// Writes `{"expected", "measured"}`, each present only once the step that
    /// establishes it passed, so that facts with neither write `{}`
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(expected, forKey: .expected)
        try container.encodeIfPresent(measured, forKey: .measured)
    }
}

extension ExpectedFacts: Encodable {
    private enum CodingKeys: String, CodingKey {
        case artifact, config, platform, measurement
        case configRepo = "config_repo"
        case codeMeasurement = "code_measurement"
    }

    /// Writes `{"config_repo", "artifact", "config", "platform",
    /// "code_measurement", "measurement"}`, with the records and measurements
    /// as `VerifiedFacts` writes them
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(configRepo, forKey: .configRepo)
        try container.encode(artifact, forKey: .artifact)
        try container.encodeIfPresent(config, forKey: .config)
        try container.encodeIfPresent(platform, forKey: .platform)
        try container.encodeIfPresent(codeMeasurement?.constrained, forKey: .codeMeasurement)
        try container.encodeIfPresent(measurement, forKey: .measurement)
    }
}

extension MeasuredFacts: Encodable {
    private enum CodingKeys: String, CodingKey {
        case cpuMeasurement = "cpu_measurement"
        case tlsPublicKeyFingerprint = "tls_public_key_fp"
        case hpkePublicKeyFingerprint = "hpke_public_key_fp"
    }

    /// Writes `{"cpu_measurement", "tls_public_key_fp", "hpke_public_key_fp"}`,
    /// each omitted when it is absent, so that facts with none of them write
    /// `{}`. The fingerprints are unverified.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(cpu?.measurement, forKey: .cpuMeasurement)
        try container.encodeIfNotEmpty(tlsPublicKeyFingerprint, forKey: .tlsPublicKeyFingerprint)
        try container.encodeIfNotEmpty(hpkePublicKeyFingerprint, forKey: .hpkePublicKeyFingerprint)
    }
}

/// A coding key that is any string, for the measurement members that a
/// platform names
struct JSONKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }

    init(_ name: String) {
        stringValue = name
    }

    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    init?(intValue: Int) {
        nil
    }
}

extension KeyedEncodingContainer {
    /// Encodes value, unless it is empty: the JSON form never writes ""
    mutating func encodeIfNotEmpty(_ value: String, forKey key: Key) throws {
        if !value.isEmpty {
            try encode(value, forKey: key)
        }
    }
}

/// The times of the JSON form: RFC 3339 in UTC, written with `Z`
enum ReportTime {
    /// The instant in UTC, with a fractional second only when it has one.
    /// `Date` holds an instant to about a microsecond, so the fraction has at
    /// most six digits.
    static func format(_ date: Date) -> String {
        let microseconds = (date.timeIntervalSince1970 * 1_000_000).rounded()
        let seconds = (microseconds / 1_000_000).rounded(.down)
        let whole = Date(timeIntervalSince1970: seconds).formatted(.iso8601)
        let fraction = Int(microseconds - seconds * 1_000_000)
        guard fraction > 0, whole.hasSuffix("Z") else {
            return whole
        }
        var digits = String(fraction)
        digits = String(repeating: "0", count: 6 - digits.count) + digits
        while digits.hasSuffix("0") {
            digits.removeLast()
        }
        return "\(whole.dropLast()).\(digits)Z"
    }

    /// Parses an RFC 3339 time, with or without a fractional second of any
    /// length, or returns nil. The fraction is read here, since Foundation's
    /// parsers keep at most milliseconds of it.
    static func parse(_ value: String) -> Date? {
        var whole = value
        var fraction = 0.0
        if let dot = value.firstIndex(of: ".") {
            let start = value.index(after: dot)
            let end = value[start...].firstIndex { !("0"..."9").contains($0) } ?? value.endIndex
            guard start < end, let parsed = Double("0." + value[start..<end]) else {
                return nil
            }
            fraction = parsed
            whole = String(value[..<dot] + value[end...])
        }
        guard let date = try? Date.ISO8601FormatStyle().parse(whole) else {
            return nil
        }
        return date.addingTimeInterval(fraction)
    }
}
