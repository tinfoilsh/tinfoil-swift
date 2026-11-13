import Foundation

/// A gateway catalog entry: the repository a model's replicas run and the
/// replicas' hosts. The gateway is not trusted: each replica is verified
/// against the repository before a request is sealed to it.
///
/// Experimental: the gateway route is new, and this API may change or be
/// removed in a later release.
public struct CatalogEntry: Sendable, Equatable, Codable {
    /// The `owner/name` repository that the model's replicas run, as the
    /// gateway reports it
    public let repo: String
    /// The replicas' hosts, each with an optional port
    public let hosts: [String]

    public init(repo: String, hosts: [String]) {
        self.repo = repo
        self.hosts = hosts
    }

    /// Whether the entry can be routed to: a bare repository of Tinfoil's,
    /// without a tag or digest, and at least one replica
    var isTrusted: Bool {
        guard repo.hasPrefix(GatewayCatalog.trustedRepoOwner), !repo.contains("@"), !hosts.isEmpty,
              let syntax = GatewayCatalog.referenceSyntax
        else {
            return false
        }
        return (try? syntax.checkRepoVerifiability(repo)) != nil
    }
}

/// A gateway catalog: model names to untrusted repository and replica
/// entries.
///
/// Experimental: the gateway route is new, and this API may change or be
/// removed in a later release.
public typealias Catalog = [String: CatalogEntry]

enum GatewayCatalog {
    static let trustedRepoOwner = "tinfoilsh/"
    static let path = "/catalog"
    static let fetchTimeout: TimeInterval = 10
    static let maximumBytes = 2 << 20
    // The gateway lists only replicas passing its health checks and reloads
    // its config every 10 seconds, so a client refreshes as often.
    static let refreshInterval: Duration = .seconds(10)

    /// Checks repository syntax with the framework's reference parser; a
    /// framework that can't build a default verifier trusts no entry.
    static let referenceSyntax: GoAttestationVerifier? = try? GoAttestationVerifier()

    /// Reads the catalog of the gateway at host, keeping only the entries that
    /// can be routed to.
    static func fetch(
        host: String,
        fetch: @Sendable (URL) async throws -> Data = {
            try await AttestationFetcher(timeout: fetchTimeout, maximumBodyBytes: maximumBytes).fetch($0)
        }
    ) async throws -> Catalog {
        // host is an authority: a host with an optional port, nothing else.
        guard !host.isEmpty, !host.contains(where: { "/?#@".contains($0) }),
              let url = URL(string: "https://\(host)\(path)"), url.host != nil, url.path == path
        else {
            throw TinfoilError.configuration("the gateway host must be a host with an optional port, not \(host)")
        }
        let body = try await fetch(url)
        let catalog: Catalog
        do {
            catalog = try JSONDecoder().decode(Catalog.self, from: body)
        } catch {
            throw TinfoilError.network("decoding gateway catalog: \(error)")
        }
        return catalog.filter { $0.value.isTrusted }
    }
}

/// Fetches the catalog on first use and refreshes it on use once the refresh
/// interval has passed. Callers share one fetch. Until a fetch succeeds,
/// callers wait for it, and a failure is retried on the next use. After that
/// callers never wait: the last catalog is returned while a refresh runs, and
/// a failed refresh keeps it for another interval.
actor CatalogCache {
    private let fetch: @Sendable () async throws -> Catalog
    private let now: @Sendable () -> ContinuousClock.Instant
    private var catalog: Catalog?
    private var refreshAt: ContinuousClock.Instant
    private var loading: Task<Catalog, Error>?

    init(
        fetch: @escaping @Sendable () async throws -> Catalog,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now }
    ) {
        self.fetch = fetch
        self.now = now
        self.refreshAt = now()
    }

    func get() async throws -> Catalog {
        if let catalog {
            if now() >= refreshAt, loading == nil {
                // Moving the deadline now keeps later callers from starting
                // another refresh; load sets it again when it finishes.
                refreshAt = now() + GatewayCatalog.refreshInterval
                loading = Task { try await self.load() }
            }
            return catalog
        }
        let task = loading ?? Task { try await self.load() }
        loading = task
        return try await waitForSharedTask(task)
    }

    private func load() async throws -> Catalog {
        defer { loading = nil }
        do {
            let fetched = try await fetch()
            catalog = fetched
            refreshAt = now() + GatewayCatalog.refreshInterval
            return fetched
        } catch {
            if catalog != nil {
                refreshAt = now() + GatewayCatalog.refreshInterval
            }
            throw error
        }
    }
}
