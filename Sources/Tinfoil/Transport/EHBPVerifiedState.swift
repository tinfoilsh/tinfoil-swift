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
    /// The report of the verification that endorses the key, or nil for a
    /// key that the caller supplied
    let verification: VerificationReport?

    init(enclaveURL: String, publicKey: Data, expiresAt: Date = .distantFuture, verification: VerificationReport? = nil) {
        self.enclaveURL = enclaveURL
        self.publicKey = publicKey
        self.expiresAt = expiresAt
        self.verification = verification
    }
}

extension EHBPVerifiedEndpoint {
    /// The endpoint that a verification of the enclave at enclaveURL
    /// endorses: the HPKE key of its verified facts, until their freshness
    /// deadline.
    init(enclaveURL: String, verification: VerificationReport) throws {
        let facts = try verification.passedFacts()
        self.init(
            enclaveURL: enclaveURL,
            publicKey: try Self.publicKey(hex: facts.hpkePublicKey),
            expiresAt: facts.freshnessExpiresAt,
            verification: verification
        )
    }

    /// The X25519 key EHBP encrypts request bodies to, from its hex form. An
    /// attestation that endorses none can't be used with EHBP.
    static func publicKey(hex: String?) throws -> Data {
        guard let hex, !hex.isEmpty else {
            throw TinfoilError.attestation("Server does not support EHBP (no HPKE public key)")
        }
        guard let key = Data(hexString: hex), key.count == TinfoilConstants.hpkePublicKeyByteCount else {
            throw TinfoilError.attestation("Invalid HPKE public key format (expected 32 bytes)")
        }
        return key
    }
}

/// Shares the active attested endpoint between regular and streaming sessions.
/// Refreshes are single-flight so concurrent stale-key responses do not trigger
/// redundant attestation work or install competing endpoint/key pairs.
internal actor EHBPVerifiedState {
    /// Returns the endpoint to use instead of `stale`, the one that expired or
    /// whose key the enclave rejected.
    typealias Refresh = @Sendable (_ stale: EHBPVerifiedEndpoint) async throws -> EHBPVerifiedEndpoint
    /// Whether an unexpired endpoint may still seal new requests
    typealias Endorses = @Sendable (_ endpoint: EHBPVerifiedEndpoint) async -> Bool

    private struct RefreshOperation {
        let id: UInt64
        let task: Task<EHBPVerifiedEndpoint, Error>
    }

    private var endpoint: EHBPVerifiedEndpoint
    private var generation: UInt64 = 0
    private let refreshEndpoint: Refresh?
    private let endorses: Endorses?
    private let now: @Sendable () -> Date
    private var nextRefreshID: UInt64 = 0
    private var refreshOperation: RefreshOperation?
    private var closed = false

    /// - Parameter endorses: Checks an unexpired endpoint before each new
    ///   request; one that it no longer endorses, as when its verification
    ///   was discarded, is refreshed first. Nil endorses every endpoint until
    ///   it expires.
    init(
        endpoint: EHBPVerifiedEndpoint,
        refresh: Refresh? = nil,
        endorses: Endorses? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.endpoint = endpoint
        self.refreshEndpoint = refresh
        self.endorses = endorses
        self.now = now
    }

    /// Refuses every later request, including the replay of one whose key
    /// was rejected, and cancels a refresh in progress.
    func close() {
        closed = true
        refreshOperation?.task.cancel()
    }

    private func checkOpen() throws {
        if closed {
            throw TinfoilError.configuration("the client is closed")
        }
    }

    /// The endpoint to seal a new request to. One whose attestation has
    /// expired, or that `endorses` no longer endorses, is refreshed first,
    /// through the same single-flight refresh as a rejected key, so neither
    /// seals a request.
    func current() async throws -> (endpoint: EHBPVerifiedEndpoint, generation: UInt64) {
        try checkOpen()
        let (cached, cachedGeneration) = (endpoint, generation)
        if now() < cached.expiresAt, await endorses?(cached) ?? true {
            try checkOpen()
            // Another request may have installed a newer endpoint while the
            // check was suspended; seal to that one instead.
            guard generation == cachedGeneration else {
                return try await current()
            }
            return (cached, cachedGeneration)
        }
        _ = try await refresh(afterRejectedGeneration: cachedGeneration)
        try checkOpen()
        guard now() < endpoint.expiresAt else {
            throw TinfoilError.attestation("refreshed attestation is already past its freshness deadline")
        }
        return (endpoint, generation)
    }

    func refresh(afterRejectedGeneration rejectedGeneration: UInt64) async throws -> EHBPVerifiedEndpoint {
        try checkOpen()
        if generation != rejectedGeneration {
            return endpoint
        }

        guard let refreshEndpoint else {
            throw TinfoilError.configuration(
                "EHBP key must be re-attested, but no attestation refresh is configured"
            )
        }

        let operation: RefreshOperation
        if let existing = refreshOperation {
            operation = existing
        } else {
            nextRefreshID &+= 1
            let stale = endpoint
            operation = RefreshOperation(
                id: nextRefreshID,
                task: Task { try await refreshEndpoint(stale) }
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
            // A refresh that finishes despite a late close seals nothing.
            try checkOpen()
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
