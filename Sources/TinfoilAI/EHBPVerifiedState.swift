import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The enclave identity that an EHBP request is currently sealed to.
internal struct EHBPVerifiedEndpoint: Sendable {
    let enclaveURL: String
    let publicKey: Data
    /// No new request may be sealed to this key at or after this instant. A
    /// key supplied by the caller rather than attested never expires.
    let expiresAt: Date

    init(enclaveURL: String, publicKey: Data, expiresAt: Date = .distantFuture) {
        self.enclaveURL = enclaveURL
        self.publicKey = publicKey
        self.expiresAt = expiresAt
    }
}

/// Shares the active attested endpoint between regular and streaming sessions.
/// Refreshes are single-flight so concurrent stale-key responses do not trigger
/// redundant attestation work or install competing endpoint/key pairs.
internal actor EHBPVerifiedState {
    typealias Refresh = @Sendable () async throws -> EHBPVerifiedEndpoint

    private struct RefreshOperation {
        let id: UInt64
        let task: Task<EHBPVerifiedEndpoint, Error>
    }

    private var endpoint: EHBPVerifiedEndpoint
    private var generation: UInt64 = 0
    private let refreshEndpoint: Refresh?
    private let now: @Sendable () -> Date
    private var nextRefreshID: UInt64 = 0
    private var refreshOperation: RefreshOperation?

    init(
        endpoint: EHBPVerifiedEndpoint,
        refresh: Refresh? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.endpoint = endpoint
        self.refreshEndpoint = refresh
        self.now = now
    }

    /// The endpoint to seal a new request to. One whose attestation has
    /// expired is refreshed first, through the same single-flight refresh as a
    /// rejected key, so an expired key never seals a request.
    func current() async throws -> (endpoint: EHBPVerifiedEndpoint, generation: UInt64) {
        if now() < endpoint.expiresAt {
            return (endpoint, generation)
        }
        _ = try await refresh(afterRejectedGeneration: generation)
        guard now() < endpoint.expiresAt else {
            throw TinfoilError.attestationError("refreshed attestation is already past its freshness deadline")
        }
        return (endpoint, generation)
    }

    func refresh(afterRejectedGeneration rejectedGeneration: UInt64) async throws -> EHBPVerifiedEndpoint {
        if generation != rejectedGeneration {
            return endpoint
        }

        guard let refreshEndpoint else {
            throw TinfoilError.invalidConfiguration(
                "EHBP key must be re-attested, but no attestation refresh is configured"
            )
        }

        let operation: RefreshOperation
        if let existing = refreshOperation {
            operation = existing
        } else {
            nextRefreshID &+= 1
            operation = RefreshOperation(
                id: nextRefreshID,
                task: Task { try await refreshEndpoint() }
            )
            refreshOperation = operation
            Task { [weak self] in
                let result = await operation.task.result
                await self?.complete(
                    operation,
                    afterRejectedGeneration: rejectedGeneration,
                    with: result
                )
            }
        }

        do {
            let refreshed = try await waitForSharedTask(operation.task)
            return install(
                refreshed,
                from: operation,
                afterRejectedGeneration: rejectedGeneration
            )
        } catch is CancellationError {
            // Cancellation belongs to this waiter. The shared refresh remains
            // alive so another in-flight request can safely reuse it.
            throw CancellationError()
        } catch {
            clearRefreshOperation(operation)
            throw error
        }
    }

    private func install(
        _ refreshed: EHBPVerifiedEndpoint,
        from operation: RefreshOperation,
        afterRejectedGeneration rejectedGeneration: UInt64
    ) -> EHBPVerifiedEndpoint {
        if generation == rejectedGeneration {
            endpoint = refreshed
            generation &+= 1
        }
        clearRefreshOperation(operation)
        return endpoint
    }

    /// Only the operation that is still current may clear the single-flight
    /// slot, so a stale completion cannot discard a newer refresh.
    private func clearRefreshOperation(_ operation: RefreshOperation) {
        if refreshOperation?.id == operation.id {
            refreshOperation = nil
        }
    }

    private func complete(
        _ operation: RefreshOperation,
        afterRejectedGeneration rejectedGeneration: UInt64,
        with result: Result<EHBPVerifiedEndpoint, Error>
    ) {
        switch result {
        case .success(let refreshed):
            _ = install(
                refreshed,
                from: operation,
                afterRejectedGeneration: rejectedGeneration
            )
        case .failure:
            clearRefreshOperation(operation)
        }
    }
}

private struct EHBPProblemDetails: Decodable { let type: String? }

internal enum EHBPProblemResponse {
    static let keyConfigurationType = "urn:ietf:params:ehbp:error:key-config"
    static let maximumDiagnosticBytes = 4 * 1024

    /// Appends at most the remaining diagnostic budget. Returns true when the
    /// source chunk was truncated and therefore cannot be parsed as a complete
    /// problem document.
    static func appendDiagnosticPrefix(_ chunk: Data, to body: inout Data) -> Bool {
        guard body.count < maximumDiagnosticBytes else {
            return !chunk.isEmpty
        }
        let remaining = maximumDiagnosticBytes - body.count
        if chunk.count > remaining {
            body.append(contentsOf: chunk.prefix(remaining))
            return true
        }
        body.append(chunk)
        return false
    }

    static func mayBeKeyConfigurationMismatch(_ response: HTTPURLResponse) -> Bool {
        guard response.statusCode == 422 else { return false }
        let contentType = response.value(forHTTPHeaderField: "Content-Type")?
            .split(separator: ";", maxSplits: 1)
            .first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return contentType == "application/problem+json"
    }

    /// Streaming retries inspect only small, length-delimited problem bodies.
    /// Generic or unbounded 422 responses reach the response delegate without
    /// waiting for a diagnostic body to be accumulated first.
    static func shouldInspectKeyConfigurationMismatch(_ response: HTTPURLResponse) -> Bool {
        let length = response.expectedContentLength
        return mayBeKeyConfigurationMismatch(response)
            && length >= 0
            && length <= Int64(maximumDiagnosticBytes)
    }

    static func isKeyConfigurationMismatch(
        response: HTTPURLResponse,
        body: Data
    ) -> Bool {
        guard mayBeKeyConfigurationMismatch(response),
              body.count <= maximumDiagnosticBytes,
              let problem = try? JSONDecoder().decode(EHBPProblemDetails.self, from: body),
              problem.type == keyConfigurationType
        else {
            return false
        }
        return true
    }
}
