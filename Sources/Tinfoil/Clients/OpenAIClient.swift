import Foundation
@_exported import OpenAI
import EHBP

/// This SDK's version
public let version = TinfoilConstants.sdkVersion

/// An HTTP client that an `OpenAIClient` can send through: an
/// `EnclaveHTTPClient`, a `RouterHTTPClient` or a `GatewayHTTPClient`. Only
/// this SDK's clients conform, since only this SDK can create the
/// `AttestedRoute` that the protocol requires.
public protocol AttestedHTTPClient: AnyObject, Sendable {
    /// Where the client sends requests
    var baseURL: URL { get }

    /// The route that the client's requests take, which an `OpenAIClient`
    /// sends through
    var attestedRoute: AttestedRoute { get }

    /// Closes the client: later requests and verifications fail with
    /// `TinfoilError.configurationError`. Requests already sent finish.
    func close() async
}

/// The route of an `AttestedHTTPClient`: its verified connection, or the
/// gateway. It has no public initializer, so that only this SDK's clients
/// can conform to `AttestedHTTPClient`.
public struct AttestedRoute: Sendable {
    enum Kind: Sendable {
        /// An enclave or router client's verified connection
        case connection(EnclaveConnection)
        /// A gateway client, which seals each request to a replica
        case gateway(GatewayHTTPClient)
    }

    let kind: Kind
}

extension EnclaveHTTPClient: AttestedHTTPClient {
    public var attestedRoute: AttestedRoute { AttestedRoute(kind: .connection(connection)) }
}

extension RouterHTTPClient: AttestedHTTPClient {
    public var attestedRoute: AttestedRoute { AttestedRoute(kind: .connection(connection)) }
}

extension GatewayHTTPClient: AttestedHTTPClient {
    public var attestedRoute: AttestedRoute { AttestedRoute(kind: .gateway(self)) }
}

/// Configures an `OpenAIClient`.
public struct OpenAIOptions: Sendable, Equatable {
    /// The path of the OpenAI API, joined under the EHBP proxy URL or, when
    /// there is none, under the enclave's origin. Nil selects "/v1/". It must
    /// be an absolute path, without a query, a fragment, an encoded slash, or
    /// a "." or ".." segment, percent-encoded or not. A gateway client's URL
    /// already carries the API path, so setting one with a gateway client is
    /// a configuration error.
    public var apiPath: String?

    public init(apiPath: String? = nil) {
        self.apiPath = apiPath
    }
}

/// An OpenAI-compatible client whose requests go through an
/// `AttestedHTTPClient`, protected as that client protects its own: over TLS
/// pinned to the attested key, or with bodies sealed by EHBP.
///
/// Over a `GatewayHTTPClient`, only requests that name a model can be
/// routed, so requests without one, such as `models()`, listing assistants,
/// or the files endpoints, fail with `TinfoilError.configurationError`; for
/// the models that the gateway serves, use `GatewayHTTPClient.models()`.
public final class OpenAIClient: OpenAICompatibleClient, Sendable {
    public let openAI: OpenAI
    /// The attested client that requests go through. Cast it to its concrete
    /// type for that type's own members.
    public let httpClient: any AttestedHTTPClient
    /// The OpenAI base URL that requests are sent to
    public let baseURL: URL

    /// Creates an OpenAI client that sends through `httpClient`. It does no
    /// network I/O: `httpClient` was verified when it was created, and
    /// verifies again by itself.
    ///
    /// The client sets the OpenAI base URL itself: `options.apiPath`, "/v1/"
    /// by default, joined under the EHBP proxy URL or, when there is none,
    /// under the enclave's origin; for a gateway client, its URL. No other
    /// parameter changes where requests go; set `options.apiPath` to change
    /// the API path.
    ///
    /// - Parameters:
    ///   - httpClient: The attested client that requests go through
    ///   - options: The client's options
    ///   - apiKey: The API key; required unless `apiKeyProvider` is given
    ///   - apiKeyProvider: Supplies the API key for each request, as for a
    ///     rotating token
    ///   - parsingOptions: Parsing options for handling different providers
    ///   - customHeaders: Headers to send on every request, merged over those
    ///     that `tinfoilEvents` adds; caller values win
    ///   - timeoutInterval: How long a request may wait for the next bytes
    ///     of its response before it fails, in seconds; 60 by default. Raise
    ///     it for long completions that send nothing until they finish.
    ///   - tinfoilEvents: Tinfoil progress events to ask the router for, as
    ///     values of the `X-Tinfoil-Events` header
    public init(
        httpClient: any AttestedHTTPClient,
        options: OpenAIOptions = OpenAIOptions(),
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        timeoutInterval: TimeInterval = 60,
        tinfoilEvents: Set<TinfoilEvent> = []
    ) throws {
        let staticApiKey = try OpenAI.apiKey(apiKey, provider: apiKeyProvider)
        let session: URLSessionProtocol
        let streamingFactory: URLSessionFactory
        let baseURL: URL
        switch httpClient.attestedRoute.kind {
        case let .connection(connection):
            baseURL = try Self.join(connection.baseURL, apiPath: options.apiPath ?? Self.defaultAPIPath)
            if let ehbp = connection.ehbp {
                session = ehbp.session
                streamingFactory = ehbp.streamingFactory
            } else {
                session = StreamingSession(delegate: nil, open: connection.open)
                streamingFactory = PinnedSessionFactory(open: connection.open)
            }
        case let .gateway(gateway):
            guard options.apiPath == nil else {
                throw TinfoilError.configuration(
                    "invalid API path: a gateway client's URL already carries the API path; set the gateway's base URL instead"
                )
            }
            baseURL = gateway.baseURL
            session = StreamingSession(delegate: nil, open: gateway.open)
            streamingFactory = PinnedSessionFactory(open: gateway.open)
        }
        self.openAI = try OpenAI.sealed(
            apiKey: staticApiKey,
            apiKeyProvider: apiKeyProvider,
            baseURL: baseURL.absoluteString,
            session: session,
            streamingFactory: streamingFactory,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            timeoutInterval: timeoutInterval,
            tinfoilEvents: tinfoilEvents
        )
        self.httpClient = httpClient
        self.baseURL = baseURL
    }

    /// Creates a client on Tinfoil's recommended route: a `RouterHTTPClient`
    /// with the default options, verified before it returns, and an
    /// `OpenAIClient` over it. The API key is checked before any network
    /// I/O. See `init(httpClient:options:…)` for the parameters.
    ///
    /// Servers that hold many end users' conversations should set the
    /// `user_cache_secret` field per request (for example through
    /// `ChatQuery.extraBody`); a non-empty per-request string wins over the
    /// client's secret.
    public convenience init(
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        timeoutInterval: TimeInterval = 60,
        tinfoilEvents: Set<TinfoilEvent> = []
    ) async throws {
        _ = try OpenAI.apiKey(apiKey, provider: apiKeyProvider)
        try self.init(
            httpClient: await RouterHTTPClient(),
            apiKey: apiKey,
            apiKeyProvider: apiKeyProvider,
            parsingOptions: parsingOptions,
            customHeaders: customHeaders,
            timeoutInterval: timeoutInterval,
            tinfoilEvents: tinfoilEvents
        )
    }

    /// Closes `httpClient`: later requests and verifications fail with
    /// `TinfoilError.configurationError`, from this client and any other over
    /// the same HTTP client. Requests already sent finish. Closing again does
    /// nothing.
    public func close() async {
        await httpClient.close()
    }

    /// The API path of an `OpenAIOptions` without one
    static let defaultAPIPath = "/v1/"

    /// `apiPath` joined under `root`, a proxy URL or an origin, whether or not
    /// `root` ends with a slash. The result ends with a slash, so that request
    /// paths join under it.
    static func join(_ root: URL, apiPath: String) throws -> URL {
        try validate(apiPath: apiPath)
        var joined = root.absoluteString
        while joined.hasSuffix("/") {
            joined.removeLast()
        }
        joined += apiPath
        if !joined.hasSuffix("/") {
            joined += "/"
        }
        guard let url = URL(string: joined) else {
            throw TinfoilError.configuration("invalid API path \"\(apiPath)\": it does not form a URL under \(root.absoluteString)")
        }
        return url
    }

    /// Requires an absolute path without a query, a fragment, an encoded
    /// slash, or a "." or ".." segment, percent-encoded or not, so that it can
    /// only name a path under its root.
    static func validate(apiPath: String) throws {
        guard apiPath.hasPrefix("/"), !apiPath.hasPrefix("//") else {
            throw TinfoilError.configuration("invalid API path \"\(apiPath)\": it must be an absolute path, such as /v1/")
        }
        guard !apiPath.contains(where: { $0 == "?" || $0 == "#" }) else {
            throw TinfoilError.configuration("invalid API path \"\(apiPath)\": it must not carry a query or a fragment")
        }
        guard let components = URLComponents(string: apiPath), components.percentEncodedPath == apiPath else {
            throw TinfoilError.configuration("invalid API path \"\(apiPath)\": it does not parse as a URL path")
        }
        for segment in apiPath.split(separator: "/", omittingEmptySubsequences: false) {
            guard let decoded = segment.removingPercentEncoding else {
                throw TinfoilError.configuration("invalid API path \"\(apiPath)\": it has an invalid percent-encoding")
            }
            if decoded == "." || decoded == ".." || decoded.contains("/") {
                throw TinfoilError.configuration(
                    "invalid API path \"\(apiPath)\": it must not contain a \".\" or \"..\" segment or an encoded slash"
                )
            }
        }
    }
}
