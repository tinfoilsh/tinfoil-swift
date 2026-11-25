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
    /// The client sets the OpenAI base URL itself: `apiPath` joined under
    /// the EHBP proxy URL or, when there is none, under the enclave's origin;
    /// for a gateway client, under its URL. No other parameter changes where
    /// requests go; set `apiPath` to change the API path.
    ///
    /// - Parameters:
    ///   - httpClient: The attested client that requests go through
    ///   - apiPath: The path of the OpenAI API on the server, "/v1/" by
    ///     default. It must be an RFC 3986 absolute path, which starts with
    ///     "/" but not "//", without a query or a fragment, holding only
    ///     path characters and well-formed percent-encodings, and without a
    ///     "." or ".." segment, an encoded slash or an encoded backslash,
    ///     percent-encoded or not; an empty path is refused, so leave it out
    ///     for the default. Its percent-encodings must decode to UTF-8, which
    ///     the OpenAI client sends. Any other path fails with
    ///     `TinfoilError.configurationError`.
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
        apiPath: String = OpenAIClient.defaultAPIPath,
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
            baseURL = try Self.join(connection.baseURL, apiPath: apiPath)
            if let ehbp = connection.ehbp {
                session = ehbp.session
                streamingFactory = ehbp.streamingFactory
            } else {
                session = StreamingSession(delegate: nil, open: connection.open)
                streamingFactory = PinnedSessionFactory(open: connection.open)
            }
        case let .gateway(gateway):
            baseURL = try Self.join(gateway.baseURL, apiPath: apiPath)
            session = StreamingSession(delegate: nil, open: gateway.open)
            streamingFactory = PinnedSessionFactory(open: gateway.open)
        }
        self.openAI = try OpenAI.sealed(
            apiKey: staticApiKey,
            apiKeyProvider: apiKeyProvider,
            baseURL: baseURL,
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
    /// `OpenAIClient` over it. The API path and the API key are checked, and
    /// the process's prompt-cache secret is generated, before any network
    /// I/O; when the secret can't be generated, this throws
    /// `SecureRandomError`. See `init(httpClient:apiPath:…)` for the
    /// parameters.
    ///
    /// Servers that hold many end users' conversations should set the
    /// `user_cache_secret` field per request (for example through
    /// `ChatQuery.extraBody`); a non-empty per-request string wins over the
    /// client's secret.
    public convenience init(
        apiPath: String = OpenAIClient.defaultAPIPath,
        apiKey: String? = nil,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        timeoutInterval: TimeInterval = 60,
        tinfoilEvents: Set<TinfoilEvent> = []
    ) async throws {
        try Self.validate(apiPath: apiPath)
        _ = try OpenAI.apiKey(apiKey, provider: apiKeyProvider)
        try self.init(
            httpClient: await RouterHTTPClient(),
            apiPath: apiPath,
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

    /// The API path when none is given
    public static let defaultAPIPath = "/v1/"

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

    /// The characters that an RFC 3986 path segment holds as they are:
    /// unreserved, sub-delims, ":" and "@"
    private static let pathCharacters = Set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@".utf8
    )

    /// Requires an RFC 3986 absolute path without a query, a fragment, an
    /// encoded slash or backslash, or a "." or ".." segment, percent-encoded
    /// or not, so that it can only name a path under its root and is sent as
    /// it was written. The OpenAI client takes the path decoded, so an
    /// encoding that doesn't decode to UTF-8 is refused too.
    static func validate(apiPath: String) throws {
        func invalid(_ reason: String) -> TinfoilError {
            .configuration("invalid API path \"\(apiPath)\": \(reason)")
        }
        guard !apiPath.isEmpty else {
            throw invalid("it is empty; leave it out for the default, \(defaultAPIPath)")
        }
        guard apiPath.hasPrefix("/"), !apiPath.hasPrefix("//") else {
            throw invalid("it must be an absolute path, such as /v1/")
        }
        guard !apiPath.contains(where: { $0 == "?" || $0 == "#" }) else {
            throw invalid("it must not carry a query or a fragment")
        }
        for segment in apiPath.utf8.split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false) {
            var decoded: [UInt8] = []
            var rest = segment[...]
            while let byte = rest.popFirst() {
                guard byte == UInt8(ascii: "%") else {
                    guard pathCharacters.contains(byte) else {
                        throw invalid("it may hold only RFC 3986 path characters; percent-encode any other")
                    }
                    decoded.append(byte)
                    continue
                }
                let hex = rest.prefix(2)
                guard hex.count == 2, hex.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 | 0x20 >= 0x61 && $0 | 0x20 <= 0x66) }),
                      let value = UInt8(String(decoding: hex, as: UTF8.self), radix: 16)
                else {
                    throw invalid("it has an invalid percent-encoding")
                }
                decoded.append(value)
                rest = rest.dropFirst(2)
            }
            if decoded == [0x2E] || decoded == [0x2E, 0x2E] || decoded.contains(0x2F) || decoded.contains(0x5C) {
                throw invalid("it must not contain a \".\" or \"..\" segment, an encoded slash or an encoded backslash")
            }
            guard String(bytes: decoded, encoding: .utf8) != nil else {
                throw invalid("its percent-encoding does not decode to UTF-8, which the OpenAI client requires")
            }
        }
    }
}
