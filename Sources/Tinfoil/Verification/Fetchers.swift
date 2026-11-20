import Foundation

/// Obtains the attestation document of an enclave for a challenge nonce, in
/// place of the client's direct fetch from the enclave. Create one with
/// `AttestationFetcher.relay(_:)`, which fetches through a relay on another
/// origin, or with `init(_:)` and a closure of your own.
///
/// The client verifies whatever a fetcher returns as it verifies a document
/// that it fetched itself, so a fetcher is not trusted: it can make
/// verification fail, but it can't make an enclave pass that wouldn't pass
/// otherwise.
///
/// A client uses its fetcher for every verification: when it is created,
/// whenever it verifies again after an expiry or a key rotation, and, on the
/// router route, for each router that discovery tries and for the fallback.
public struct AttestationFetcher: Sendable {
    /// Fetches the document of `host`, a host with an optional port, for
    /// `nonce`, the fresh challenge that the document must answer
    typealias Fetch = @Sendable (_ host: String, _ nonce: Data) async throws -> Data

    let fetch: Fetch
    /// The relay's URL, checked when a client is created; nil for a closure
    let relayURL: URL?

    /// A fetcher that calls `fetch` with the enclave's host, with an optional
    /// port, and the challenge nonce that the document must answer, and
    /// returns the document's bytes.
    ///
    /// It runs for at most 30 seconds; a verification that several callers
    /// share is not any one caller's, so a caller's cancellation ends only
    /// that caller's wait. An error that it throws is reported as
    /// `TinfoilError.networkError`, unless it already is a `TinfoilError`,
    /// which keeps its case. It may be called concurrently.
    public init(_ fetch: @escaping @Sendable (_ host: String, _ nonce: Data) async throws -> Data) {
        self.fetch = fetch
        self.relayURL = nil
    }

    private init(relayURL: URL, fetch: @escaping Fetch) {
        self.fetch = fetch
        self.relayURL = relayURL
    }

    /// A fetcher that fetches documents through a relay, such as an endpoint
    /// on the application's own origin that forwards each request to the
    /// enclave that it names. A client that shouldn't reveal its IP address
    /// to enclaves, or that may reach only one origin, then reaches only the
    /// relay.
    ///
    /// It sends `GET {url}/.well-known/tinfoil-attestation?nonce={nonce}&enclave={host}`,
    /// where `nonce` is the challenge in lowercase hex and `host` is the
    /// enclave's host, with its port, encoded as a query value, with the SDK
    /// identity headers that a direct fetch sends. A `2xx` response's body is
    /// the document. It applies the bounds of a direct fetch: 30 seconds,
    /// 32 MiB, and no redirect to a URL that isn't HTTPS.
    ///
    /// - Parameter url: The relay's base URL. Its path, if any, is where the
    ///   relay is mounted: the request path joins under it, whether or not it
    ///   ends with "/". It must use HTTPS; `http` is accepted only when its
    ///   host is `localhost` or a loopback IP address. A URL with
    ///   credentials, a query or a fragment, even an empty one, is refused
    ///   when a client is created, before any network I/O.
    public static func relay(_ url: URL) -> AttestationFetcher {
        relay(url, get: { try await DocumentFetcher().fetch($0, allowingLoopbackHTTP: true) })
    }

    /// `relay(_:)` with the GET that it sends through, for tests
    static func relay(_ url: URL, get: @escaping @Sendable (URL) async throws -> Data) -> AttestationFetcher {
        AttestationFetcher(relayURL: url) { host, nonce in
            try await get(relayAttestationURL(url, host: host, nonce: nonce))
        }
    }

    /// `{relay}/.well-known/tinfoil-attestation?nonce={hex}&enclave={host}`
    static func relayAttestationURL(_ relay: URL, host: String, nonce: Data) throws -> URL {
        let nonceHex = nonce.map { String(format: "%02x", $0) }.joined()
        guard let enclave = host.addingPercentEncoding(withAllowedCharacters: .queryValueUnreserved),
              let url = URL(string: joined(relay, path: ".well-known/tinfoil-attestation") + "?nonce=\(nonceHex)&enclave=\(enclave)")
        else {
            throw TinfoilError.configuration("cannot form an attestation relay URL under \(relay.absoluteString) for \(host)")
        }
        return url
    }

    /// Fetches through the closure, bounded to 30 seconds, and gives its
    /// errors their category: a `TinfoilError` keeps its case, a cancellation
    /// passes through, and any other error is a network error.
    func callAsFunction(host: String, nonce: Data, timeout: TimeInterval = 30) async throws -> Data {
        do {
            return try await withThrowingTaskGroup(of: Data?.self) { group in
                group.addTask { try await fetch(host, nonce) }
                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                    return nil
                }
                defer { group.cancelAll() }
                guard let document = try await group.next() ?? nil else {
                    throw TinfoilError.network("fetching the attestation of \(host) timed out after \(Int(timeout)) seconds")
                }
                return document
            }
        } catch let error as TinfoilError {
            throw error
        } catch let error as CancellationError {
            throw error
        } catch {
            if Task.isCancelled {
                throw CancellationError()
            }
            throw TinfoilError.network("fetching the attestation of \(host): \(error)")
        }
    }
}

/// Obtains the candidate routers for router discovery, in place of the
/// client's fetch from `https://atc.tinfoil.sh/routers`. Create one with
/// `RouterListFetcher.relay(_:)` or with `init(_:)` and a closure of your own.
///
/// The list is not trusted to make a router pass: it only proposes hosts, and
/// discovery verifies each one before it uses it, tries them in a random order
/// for at most 30 seconds in all, and falls back to `inference.tinfoil.sh`
/// when none passes. Any error counts as an empty list.
///
/// An attestation document doesn't name the host that serves it, so the list
/// source is trusted not to name a host that would relay another router's
/// attestation: with EHBP, such a host would receive the request headers,
/// including the API key, although not the sealed bodies.
public struct RouterListFetcher: Sendable {
    typealias Fetch = @Sendable () async throws -> [String]

    let fetch: Fetch
    /// The relay's URL, checked when a client is created; nil for a closure
    let relayURL: URL?

    /// A fetcher that calls `fetch` for the list of router hosts. An error
    /// that it throws counts as an empty list, even when the list is partial.
    public init(_ fetch: @escaping @Sendable () async throws -> [String]) {
        self.fetch = fetch
        self.relayURL = nil
    }

    private init(relayURL: URL, fetch: @escaping Fetch) {
        self.fetch = fetch
        self.relayURL = relayURL
    }

    /// A fetcher that fetches the list through a relay, such as an endpoint
    /// on the application's own origin that forwards the request to
    /// `https://atc.tinfoil.sh/routers`.
    ///
    /// It sends `GET {url}/routers` and reads the response as a direct fetch's:
    /// a JSON array of host strings of at most 32 MiB, fetched with no
    /// redirect to a URL that isn't HTTPS.
    ///
    /// - Parameter url: The relay's base URL, under the rules of
    ///   `AttestationFetcher.relay(_:)`.
    public static func relay(_ url: URL) -> RouterListFetcher {
        relay(url, get: { try await DocumentFetcher().fetch($0, allowingLoopbackHTTP: true) })
    }

    /// `relay(_:)` with the GET that it sends through, for tests
    static func relay(_ url: URL, get: @escaping @Sendable (URL) async throws -> Data) -> RouterListFetcher {
        RouterListFetcher(relayURL: url) {
            guard let listURL = URL(string: joined(url, path: "routers")) else {
                throw TinfoilError.configuration("cannot form a router list relay URL under \(url.absoluteString)")
            }
            return try parseRouterList(await get(listURL))
        }
    }

    /// The hosts of a router list response: a JSON array of strings
    static func parseRouterList(_ data: Data) throws -> [String] {
        do {
            return try JSONDecoder().decode([String].self, from: data)
        } catch {
            throw TinfoilError.network("the router list is not a JSON array of strings")
        }
    }
}

/// `path` joined under `base`'s path, with the same result whether or not
/// that path ends with "/"
private func joined(_ base: URL, path: String) -> String {
    var root = base.absoluteString
    while root.hasSuffix("/") {
        root.removeLast()
    }
    return root + "/" + path
}

private extension CharacterSet {
    /// RFC 3986 unreserved characters, which a query value carries unescaped
    static let queryValueUnreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
}
