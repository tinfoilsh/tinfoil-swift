import Foundation
@testable import Tinfoil

/// An OpenAI-compatible client that seals to a fixed enclave key, without
/// an attested HTTP client, for tests of the EHBP session and the OpenAI
/// glue. `userCacheSecret` is the already-resolved prompt-cache scoping
/// secret (see `UserCacheSecret.resolve`). `expiresAt` is when the key's
/// attestation stops authorizing new requests.
final class SealedClient: OpenAICompatibleClient, Sendable {
    let openAI: OpenAI
    private let verifiedState: EHBPVerifiedState

    init(
        apiKey: String?,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        baseURL: String,
        enclaveURL: String,
        hpkePublicKeyHex: String?,
        expiresAt: Date = .distantFuture,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        timeoutInterval: TimeInterval = 60,
        tinfoilEvents: Set<TinfoilEvent> = [],
        userCacheSecret: String = "",
        refreshEndpoint: EHBPVerifiedState.Refresh? = nil
    ) throws {
        let verifiedState = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(
                enclaveURL: enclaveURL,
                publicKey: try EHBPVerifiedEndpoint.publicKey(hex: hpkePublicKeyHex),
                expiresAt: expiresAt
            ),
            refresh: refreshEndpoint
        )
        self.verifiedState = verifiedState
        self.openAI = try OpenAI.sealed(
            apiKey: apiKey,
            apiKeyProvider: apiKeyProvider,
            baseURL: baseURL,
            session: EHBPURLSession(baseURL: baseURL, verifiedState: verifiedState, userCacheSecret: userCacheSecret),
            streamingFactory: EHBPURLSessionFactory(baseURL: baseURL, verifiedState: verifiedState, userCacheSecret: userCacheSecret),
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            timeoutInterval: timeoutInterval,
            tinfoilEvents: tinfoilEvents
        )
    }

    func close() async {
        await verifiedState.close()
    }
}
