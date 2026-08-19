import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The enclave identity that an EHBP request is currently sealed to.
internal struct EHBPVerifiedEndpoint: Sendable {
    let enclaveURL: String
    let publicKey: Data
}

/// Shares the active attested endpoint between regular and streaming sessions.
/// Refreshes are single-flight so concurrent stale-key responses do not trigger
/// redundant attestation work or install competing endpoint/key pairs.
internal actor EHBPVerifiedState {
    typealias Refresh = @Sendable () async throws -> EHBPVerifiedEndpoint

    private var endpoint: EHBPVerifiedEndpoint
    private var generation: UInt64 = 0
    private let refreshEndpoint: Refresh?
    private var refreshTask: Task<EHBPVerifiedEndpoint, Error>?

    init(endpoint: EHBPVerifiedEndpoint, refresh: Refresh? = nil) {
        self.endpoint = endpoint
        self.refreshEndpoint = refresh
    }

    func snapshot() -> (endpoint: EHBPVerifiedEndpoint, generation: UInt64) {
        (endpoint, generation)
    }

    func refresh(afterRejectedGeneration rejectedGeneration: UInt64) async throws -> EHBPVerifiedEndpoint {
        if generation != rejectedGeneration {
            return endpoint
        }

        guard let refreshEndpoint else {
            throw TinfoilError.invalidConfiguration(
                "EHBP key configuration changed, but no attestation refresh is configured"
            )
        }

        if let refreshTask {
            let refreshed = try await refreshTask.value
            if generation == rejectedGeneration {
                endpoint = refreshed
                generation &+= 1
            }
            return endpoint
        }

        let task = Task { try await refreshEndpoint() }
        refreshTask = task
        do {
            let refreshed = try await task.value
            if generation == rejectedGeneration {
                endpoint = refreshed
                generation &+= 1
            }
            refreshTask = nil
            return endpoint
        } catch {
            refreshTask = nil
            throw error
        }
    }
}

private struct EHBPProblemDetails: Decodable {
    let type: String?
    let title: String?
}

internal enum EHBPProblemResponse {
    static let keyConfigurationType = "urn:ietf:params:ehbp:error:key-config"
    static let maximumDiagnosticBytes = 64 * 1024

    static func mayBeKeyConfigurationMismatch(_ response: HTTPURLResponse) -> Bool {
        guard response.statusCode == 422 else { return false }
        let contentType = response.value(forHTTPHeaderField: "Content-Type")?
            .split(separator: ";", maxSplits: 1)
            .first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return contentType == "application/problem+json"
    }

    static func keyConfigurationMismatchTitle(
        response: HTTPURLResponse,
        body: Data
    ) -> String? {
        guard mayBeKeyConfigurationMismatch(response),
              body.count <= maximumDiagnosticBytes,
              let problem = try? JSONDecoder().decode(EHBPProblemDetails.self, from: body),
              problem.type == keyConfigurationType
        else {
            return nil
        }
        return problem.title?.isEmpty == false
            ? problem.title
            : "key configuration mismatch"
    }
}
