import CryptoKit
import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Pins a gateway model to `tinfoilsh/name[@tag][@sha256:digest]`.
///
/// Experimental: the gateway route is new, and this API may change or be
/// removed in a later release.
public struct ModelPin: Sendable {
    public let repo: String
    /// The pin's trust policy: nil inherits the gateway client's; a verifier
    /// replaces it.
    public let verifier: Verifier?

    public init(repo: String, verifier: Verifier? = nil) {
        self.repo = repo
        self.verifier = verifier
    }
}

/// A gateway replica's last successful verification.
///
/// Experimental: the gateway route is new, and this API may change or be
/// removed in a later release.
public struct ReplicaVerification: Sendable, Equatable {
    /// The replica the verification is for
    public let host: String
    /// The model names requests to the replica gave, sorted. They are what
    /// the caller asked for, not attested identities.
    public let models: [String]
    /// The repository the replica was verified against
    public let reference: String
    /// The model whose pin the replica was verified under, or "" for an
    /// unpinned model
    public let pinnedModel: String
    public let verification: Verification
}

/// One replica's verification and sealed transport, as the router uses it.
/// `EnclaveConnection` is the production one.
protocol GatewayReplica: Sendable {
    /// A verification that is valid now, with an HPKE key to seal to
    func usableVerification() async throws -> Verification
    /// Sends a request sealed to the replica, returning once its headers
    /// arrive
    func open(_ request: URLRequest) async throws -> RecoverableResponse
    var current: Verification? { get async }
    func close() async
}

extension EnclaveConnection: GatewayReplica {
    func usableVerification() async throws -> Verification {
        try await ensureUsable()
    }

    func open(_ request: URLRequest) async throws -> RecoverableResponse {
        try await recoverableBytes(for: request)
    }
}

/// Which models the gateway client serves, and the repository and trust
/// policy each model's replicas are verified against
struct GatewayPolicy: Sendable {
    struct Pin: Sendable {
        let repo: String
        let attestor: Attestor
    }

    let pins: [String: Pin]
    let pinnedOnly: Bool
    /// The policy for unpinned models
    let attestor: Attestor

    /// - Parameter pins: Each pinned model's repository and its own policy,
    ///   or nil to inherit `attestor`
    init(pins: [String: (repo: String, attestor: Attestor?)], pinnedOnly: Bool, attestor: Attestor) throws {
        if pinnedOnly && pins.isEmpty {
            throw TinfoilError.configuration("pinned-only mode requires at least one model pin")
        }
        // Replicas are verified against repository pins, so a policy whose
        // config the caller supplies or approves has nothing to check.
        if attestor.callerAuthorizesConfig {
            throw TinfoilError.configuration(Self.callerAuthorizedConfig)
        }
        var checked: [String: Pin] = [:]
        for (model, pin) in pins {
            let pinAttestor = pin.attestor ?? attestor
            if pinAttestor.callerAuthorizesConfig {
                throw TinfoilError.configuration("model \"\(model)\": \(Self.callerAuthorizedConfig)")
            }
            guard !model.trimmingCharacters(in: .whitespaces).isEmpty, pin.repo.hasPrefix(GatewayCatalog.trustedRepoOwner) else {
                throw TinfoilError.configuration(
                    "model pin \"\(model)\" repository \"\(pin.repo)\" must belong to \(GatewayCatalog.trustedRepoOwner)"
                )
            }
            do {
                try pinAttestor.checkRepoVerifiability(pin.repo)
            } catch let error as TinfoilError {
                throw TinfoilError.configuration("model \"\(model)\": \(error.message)")
            }
            checked[model] = Pin(repo: pin.repo, attestor: pinAttestor)
        }
        self.pins = checked
        self.pinnedOnly = pinnedOnly
        self.attestor = attestor
    }

    private static let callerAuthorizedConfig = "caller-authorized config requires a direct enclave client"

    /// The hosts that serve model and the replica, without its host, that a
    /// request for it is verified as
    func resolve(_ model: String, in catalog: Catalog) throws -> (hosts: [String], replica: GatewayRouter.Replica) {
        let pin = pins[model]
        if pinnedOnly && pin == nil {
            throw TinfoilError.configuration("model \"\(model)\" is not pinned")
        }
        guard let entry = catalog[model], entry.isTrusted else {
            throw TinfoilError.configuration(
                "model \"\(model)\" has no valid bare \(GatewayCatalog.trustedRepoOwner) repository with replicas in the gateway catalog"
            )
        }
        guard let pin else {
            return (entry.hosts, GatewayRouter.Replica(host: "", reference: entry.repo, pinnedModel: ""))
        }
        let repo = pin.repo.split(separator: "@", maxSplits: 1).first.map(String.init) ?? pin.repo
        guard entry.repo == repo else {
            throw TinfoilError.attestation("model \"\(model)\": expected repository \"\(repo)\", gateway offered \"\(entry.repo)\"")
        }
        return (entry.hosts, GatewayRouter.Replica(host: "", reference: pin.repo, pinnedModel: model))
    }

    /// The policy a replica is verified under
    func attestor(for replica: GatewayRouter.Replica) -> Attestor {
        pins[replica.pinnedModel]?.attestor ?? attestor
    }
}

/// Seals each request to a verified replica of the model it names. Cache
/// prefixes keep a conversation on one replica across requests.
actor GatewayRouter {
    /// A replica as verified: its host, the repository, and the pinned model
    /// whose policy applies ("" for an unpinned model). One host can be
    /// verified under several.
    struct Replica: Hashable, Sendable {
        var host: String
        let reference: String
        let pinnedModel: String
    }

    typealias MakeReplica = @Sendable (Replica, Attestor) throws -> any GatewayReplica

    static let maximumSealRedirects = 3
    static let maximumRerouted = 1024

    nonisolated let baseURL: URL
    private let policy: GatewayPolicy
    private let catalog: @Sendable () async throws -> Catalog
    private let secret: String
    private let makeReplica: MakeReplica
    private var replicas: [Replica: (replica: any GatewayReplica, models: Set<String>)] = [:]
    /// Cache prefix to the host the gateway last routed it to
    private var rerouted: [String: String] = [:]
    private var closed = false

    init(
        baseURL: URL,
        policy: GatewayPolicy,
        catalog: @escaping @Sendable () async throws -> Catalog,
        secret: String,
        makeReplica: @escaping MakeReplica
    ) {
        self.baseURL = baseURL
        self.policy = policy
        self.catalog = catalog
        self.secret = secret
        self.makeReplica = makeReplica
    }

    func close() async {
        closed = true
        for entry in replicas.values {
            await entry.replica.close()
        }
    }

    private func checkOpen() throws {
        if closed {
            throw TinfoilError.configuration("the client is closed")
        }
    }

    private func catalogNow() async throws -> Catalog {
        try checkOpen()
        let catalog = try await catalog()
        try checkOpen()
        return catalog
    }

    /// The catalog's models that the policy serves, sorted, without
    /// verifying replicas
    func models() async throws -> [String] {
        let catalog = try await catalogNow()
        return catalog.keys.filter { (try? policy.resolve($0, in: catalog)) != nil }.sorted()
    }

    /// A verification that is valid now of a replica serving model. Replicas
    /// are tried in a fixed order for the model, so repeated calls verify the
    /// same replica while it stays valid.
    func ensureVerified(model: String) async throws -> Verification {
        let catalog = try await catalogNow()
        let (hosts, base) = try policy.resolve(model, in: catalog)
        var failure: Error?
        for host in Self.rank(hosts, prefix: model, first: "") {
            try Task.checkCancellation()
            do {
                return try await verified(base.on(host)).verification
            } catch {
                try checkOpen()
                failure = error
            }
        }
        throw failure ?? TinfoilError.configuration("model \"\(model)\" has no replicas")
    }

    /// The last successful verification of each replica used so far, without
    /// checking them. They may have expired or been rejected.
    var current: [ReplicaVerification] {
        get async {
            var results: [ReplicaVerification] = []
            for (key, entry) in replicas {
                if let verification = await entry.replica.current {
                    results.append(ReplicaVerification(
                        host: key.host,
                        models: entry.models.sorted(),
                        reference: key.reference,
                        pinnedModel: key.pinnedModel,
                        verification: verification
                    ))
                }
            }
            return results.sorted {
                ($0.host, $0.reference, $0.pinnedModel) < ($1.host, $1.reference, $1.pinnedModel)
            }
        }
    }

    /// Prepares request, picks a verified replica of the model it names, and
    /// sends it sealed to that replica, following the gateway to another
    /// replica, verified first, when it answers that it routed the request
    /// elsewhere. Returns once the response's headers arrive.
    func open(_ request: URLRequest) async throws -> RecoverableResponse {
        try checkOpen()
        // Each replica makes the same check; making it here refuses a request
        // before the catalog is read or a replica verified.
        try refuseUnsealedTraffic(request)
        var resolved = request
        if let url = request.url, url.host == nil {
            resolved.url = URL(string: url.relativeString, relativeTo: baseURL)?.absoluteURL
        }
        let prepared = try GatewayRequest.prepare(resolved, secret: secret)
        let model = prepared.value(forHTTPHeaderField: GatewayRequest.modelHeader) ?? ""
        let catalog = try await catalogNow()
        let (hosts, base) = try policy.resolve(model, in: catalog)
        let prefix = prepared.value(forHTTPHeaderField: GatewayRequest.cachePrefixHeader) ?? ""

        var chosen: (replica: Replica, transport: any GatewayReplica)?
        var failure: Error?
        for host in Self.rank(hosts, prefix: prefix, first: rerouted[prefix] ?? "") {
            try Task.checkCancellation()
            do {
                let replica = base.on(host)
                chosen = (replica, try await verified(replica).transport)
                break
            } catch {
                try checkOpen()
                failure = error
            }
        }
        guard var (replica, transport) = chosen else {
            throw failure ?? TinfoilError.configuration("model \"\(model)\" has no replicas")
        }

        var redirects = 0
        while true {
            var sealed = prepared
            sealed.setValue(replica.host, forHTTPHeaderField: GatewayRequest.sealHeader)
            replicas[replica]?.models.insert(model)
            let response = try await transport.open(sealed)
            let routed = response.response.value(forHTTPHeaderField: GatewayRequest.sealHeader) ?? ""
            guard response.response.statusCode == 412, !routed.isEmpty, routed != replica.host else {
                return response
            }
            guard redirects < Self.maximumSealRedirects else {
                throw TinfoilError.network("gateway kept routing away from the enclave the request was sealed to (last: \(routed))")
            }
            redirects += 1
            replica = base.on(routed)
            do {
                transport = try await verified(replica).transport
            } catch let error as TinfoilError {
                throw error.prefixed("following gateway route to enclave \(routed)")
            }
            remember(prefix, routed)
        }
    }

    /// replica's transport once it verifies, so that a caller can fall over
    /// to another replica before sealing anything to it
    private func verified(_ replica: Replica) async throws -> (transport: any GatewayReplica, verification: Verification) {
        try checkOpen()
        let transport: any GatewayReplica
        if let existing = replicas[replica] {
            transport = existing.replica
        } else {
            transport = try makeReplica(replica, policy.attestor(for: replica))
            replicas[replica] = (transport, [])
        }
        let verification = try await transport.usableVerification()
        try checkOpen()
        return (transport, verification)
    }

    private func remember(_ prefix: String, _ host: String) {
        guard !prefix.isEmpty else {
            return
        }
        if rerouted.count >= Self.maximumRerouted {
            rerouted = [:]
        }
        rerouted[prefix] = host
    }

    /// hosts ordered by rendezvous score for a cache prefix, with first, if
    /// it is one of them, ahead of the rest; in random order without a prefix
    static func rank(_ hosts: [String], prefix: String, first: String) -> [String] {
        guard !prefix.isEmpty else {
            return hosts.shuffled()
        }
        func score(_ host: String) -> UInt64 {
            SHA256.hash(data: Data((prefix + "\u{0}" + host).utf8)).prefix(8).reduce(0) { $0 << 8 | UInt64($1) }
        }
        var ranked = hosts.sorted { score($0) > score($1) }
        if let index = ranked.firstIndex(of: first), index > 0 {
            ranked.remove(at: index)
            ranked.insert(first, at: 0)
        }
        return ranked
    }
}

extension GatewayRouter.Replica {
    func on(_ host: String) -> Self {
        var replica = self
        replica.host = host
        return replica
    }
}

extension TinfoilError {
    /// The same error, its message led by context
    func prefixed(_ context: String) -> TinfoilError {
        switch self {
        case .configurationError(let failure):
            .configuration("\(context): \(failure.message)")
        case .networkError(let failure):
            .network("\(context): \(failure.message)", urlError: failure.urlError, status: failure.status)
        case .attestationError(let failure):
            .attestation("\(context): \(failure.message)", layer: failure.layer)
        }
    }
}
