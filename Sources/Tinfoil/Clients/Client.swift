import Foundation
@_exported import OpenAI
import EHBP

/// This SDK's version
public let version = TinfoilConstants.sdkVersion

/// An OpenAI-compatible client for inference on Tinfoil's default route.
/// Every request goes to a verified enclave over a connection pinned to the
/// enclave's attested TLS key.
///
/// It takes only OpenAI-level options and exposes nothing about the route,
/// so the route can change without breaking callers. To choose the enclave,
/// pin a repo, tighten the verification policy, send through a proxy or
/// observe verifications, use `EnclaveOpenAIClient` or `RouterOpenAIClient`.
public final class Client: OpenAICompatibleClient, Sendable {
    public let openAI: OpenAI
    /// Closes whatever the route sends through
    private let closeRoute: @Sendable () async -> Void

    private init(openAI: OpenAI, close: @escaping @Sendable () async -> Void) {
        self.openAI = openAI
        self.closeRoute = close
    }

    /// Closes the client: later requests fail with
    /// `TinfoilError.configurationError`, and a verification in progress is
    /// cancelled. Requests already sent finish. Closing again does nothing.
    public func close() async {
        await closeRoute()
    }

    /// Creates a client on Tinfoil's default route, verified before it
    /// returns. The API key is checked before any network I/O.
    /// - Parameters:
    ///   - apiKey: The API key; required unless `apiKeyProvider` is given
    ///   - apiKeyProvider: Supplies the API key for each request, as for a
    ///     rotating token
    ///   - parsingOptions: Parsing options for handling different providers
    ///   - customHeaders: Headers to send on every request, merged over those
    ///     `tinfoilEvents` adds; caller values win
    ///   - timeoutInterval: How long a request may wait for the next bytes
    ///     of its response before it fails, in seconds; 60 by default. Raise
    ///     it for long completions that send nothing until they finish.
    ///   - tinfoilEvents: Tinfoil progress events to opt into. Each adds a
    ///     value to the `X-Tinfoil-Events` header, so the router emits
    ///     `<tinfoil-event>...</tinfoil-event>` markers inline with the
    ///     assistant text, which callers parse and strip before display.
    ///
    /// Servers holding many end users' conversations should set the
    /// `user_cache_secret` field per request (e.g. via `ChatQuery.extraBody`);
    /// a non-empty per-request string wins over the client's secret.
    public convenience init(
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        timeoutInterval: TimeInterval = 60,
        tinfoilEvents: Set<TinfoilEvent> = []
    ) async throws {
        // Today the default route is one of Tinfoil's routers.
        let route = try await RouterOpenAIClient(
            apiKey: apiKey,
            apiKeyProvider: apiKeyProvider,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            timeoutInterval: timeoutInterval,
            tinfoilEvents: tinfoilEvents
        )
        let httpClient = route.httpClient
        self.init(openAI: route.openAI, close: { await httpClient.close() })
    }

    /// Internal initializer that seals to a fixed enclave key, for tests.
    /// `userCacheSecret` is the already-resolved prompt-cache scoping secret
    /// (see `UserCacheSecret.resolve`). `expiresAt` is when the key's
    /// attestation stops authorizing new requests.
    internal convenience init(
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
        self.init(openAI: try OpenAI.sealed(
            apiKey: apiKey,
            apiKeyProvider: apiKeyProvider,
            baseURL: baseURL,
            session: EHBPURLSession(baseURL: baseURL, verifiedState: verifiedState, userCacheSecret: userCacheSecret),
            streamingFactory: EHBPURLSessionFactory(baseURL: baseURL, verifiedState: verifiedState, userCacheSecret: userCacheSecret),
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            timeoutInterval: timeoutInterval,
            tinfoilEvents: tinfoilEvents
        ), close: { await verifiedState.close() })
    }
}
