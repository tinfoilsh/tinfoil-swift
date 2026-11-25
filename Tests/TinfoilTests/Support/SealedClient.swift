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
        // The API path joins under the base URL, as OpenAIClient joins it.
        guard let root = URL(string: baseURL) else {
            throw TinfoilError.configuration("invalid base URL \(baseURL)")
        }
        self.openAI = try OpenAI.sealed(
            apiKey: apiKey,
            apiKeyProvider: apiKeyProvider,
            baseURL: OpenAIClient.join(root, apiPath: OpenAIClient.defaultAPIPath),
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
