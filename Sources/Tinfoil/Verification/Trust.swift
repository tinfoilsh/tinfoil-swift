import Foundation
import TinfoilGo

/// Names who vouches for the config that an enclave runs. Create one with a
/// static factory: `.repo(_:)`, `.project(_:registryIDs:)`,
/// `.signedBy(keys:project:)`, `.authorizedBy(_:)`, `.embeddedConfig(_:name:)`
/// or `.either(repo:project:)`. Only `.repo` and `.either` accept
/// attestation-collaterals/v2; every other kind requires
/// attestation-collaterals/v3.
///
/// A client checks its trust before any network I/O, and throws
/// `TinfoilError.configurationError` for one that names nothing, such as an
/// empty repository, so that a missing value can't widen the trust by
/// accident.
public struct Trust: Sendable {
    /// Tinfoil's public config registry. To accept configs from a private
    /// registry as well as public ones, list both in
    /// `.project(_:registryIDs:)`.
    public static let publicRegistryID: String = MobilePublicRegistryID

    enum Kind: Sendable {
        case repo(String)
        case project(String, registryIDs: [String]?)
        case signedBy(keys: [String], project: String?)
        case authorizedBy(ConfigAuthorizer)
        case embeddedConfig(Data, name: String)
        case either(repo: String, project: String)
    }

    let kind: Kind

    /// Trusts the signed releases of `repo`, a GitHub repository
    /// `owner/name[@tag][@sha256:digest]`, through v2 collateral.
    public static func repo(_ repo: String) -> Trust {
        Trust(kind: .repo(repo))
    }

    /// Trusts v3 collateral for `project`, a config registry project
    /// `org/project[@revision][@sha256:digest]`, that one of the trusted
    /// registries endorses.
    ///
    /// - Parameter registryIDs: The trusted registries. Nil trusts Tinfoil's
    ///   public registry alone. A list trusts exactly the registries that it
    ///   names, in place of the public registry; to trust a private registry
    ///   alongside the public one, list `Trust.publicRegistryID` too. An
    ///   empty list is refused, so that an empty list that the application
    ///   computed fails closed rather than widening the trust to the public
    ///   registry.
    public static func project(_ project: String, registryIDs: [String]? = nil) -> Trust {
        Trust(kind: .project(project, registryIDs: registryIDs))
    }

    /// Trusts v3 configs whose approvals the caller's `keys`, PEM `PUBLIC KEY`
    /// blocks, sign, in place of Tinfoil's registry. `keys` must not be
    /// empty.
    ///
    /// - Parameter project: A config registry project,
    ///   `org/project[@revision][@sha256:digest]`, that restricts the configs
    ///   that are accepted; nil or empty accepts any config that `keys` sign.
    public static func signedBy(keys: [String], project: String? = nil) -> Trust {
        Trust(kind: .signedBy(keys: keys, project: project))
    }

    /// Trusts v3 configs that `authorize` accepts, in place of a registry
    /// endorsement. The runtime, platform and hardware are still verified, but
    /// approving a config authenticates no registry, name or approval time,
    /// so this trust has no pin.
    public static func authorizedBy(_ authorize: @escaping ConfigAuthorizer) -> Trust {
        Trust(kind: .authorizedBy(authorize))
    }

    /// Trusts v3 collateral for exactly the config `bytes` that the caller
    /// supplies, which must come from trusted client configuration. It has no
    /// pin, because a pin would only compare the caller's input against the
    /// caller's input.
    ///
    /// - Parameter name: Associates the config with an
    ///   `/org/project/revision` identity; empty gives it none.
    public static func embeddedConfig(_ bytes: Data, name: String = "") -> Trust {
        Trust(kind: .embeddedConfig(bytes, name: name))
    }

    /// Trusts v2 collateral for `repo` or v3 collateral for `project`, as
    /// `.repo(_:)` and `.project(_:)` do. It exists for the migration from v2
    /// to v3 collateral and will be removed with v2.
    public static func either(repo: String, project: String) -> Trust {
        Trust(kind: .either(repo: repo, project: project))
    }

    /// The GitHub repository that each verification is pinned to, or nil
    /// when the trust names none
    public var repo: String? {
        switch kind {
        case let .repo(repo), let .either(repo, _):
            return repo
        case .project, .signedBy, .authorizedBy, .embeddedConfig:
            return nil
        }
    }

    /// The config registry project that each verification is pinned to, or
    /// nil when the trust names none
    public var project: String? {
        switch kind {
        case let .project(project, _), let .either(_, project):
            return project
        case let .signedBy(_, project):
            return project?.isEmpty == true ? nil : project
        case .repo, .authorizedBy, .embeddedConfig:
            return nil
        }
    }

    /// The pin that each verification is made against, after checking what
    /// the kind of trust itself requires; the verifier checks the values.
    func pin() throws -> Pin {
        switch kind {
        case let .repo(repo):
            guard !repo.isEmpty else {
                throw TinfoilError.configuration("a repo trust requires a repository")
            }
            return Pin(repo: repo)
        case let .project(project, registryIDs):
            guard !project.isEmpty else {
                throw TinfoilError.configuration("a project trust requires a project")
            }
            if registryIDs?.isEmpty == true {
                throw TinfoilError.configuration(
                    "a project trust's registry IDs must not be empty; leave them nil to trust the public registry"
                )
            }
            return Pin(project: project)
        case let .signedBy(_, project):
            guard let project, !project.isEmpty else {
                return .none
            }
            return Pin(project: project)
        case .authorizedBy, .embeddedConfig:
            return .none
        case let .either(repo, project):
            guard !repo.isEmpty, !project.isEmpty else {
                throw TinfoilError.configuration("an either trust requires both a repository and a project")
            }
            return Pin(repo: repo, project: project)
        }
    }
}

extension Trust {
    /// The trust that `pin` comes from, for a connection built from a pin
    /// alone, as in tests.
    init(pin: Pin) {
        switch (pin.repo, pin.project) {
        case let (repo?, project?):
            self = .either(repo: repo, project: project)
        case let (repo?, nil):
            self = .repo(repo)
        case let (nil, project?):
            self = .project(project)
        case (nil, nil):
            self = .authorizedBy { _ in }
        }
    }
}
