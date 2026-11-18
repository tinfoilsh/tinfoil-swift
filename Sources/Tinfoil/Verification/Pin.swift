/// Names what an enclave must run. `repo` and `project` are separate
/// namespaces with unrelated owners, so neither is satisfied by the other's
/// evidence: a repository only by its signed release, a project only by a
/// registry deployment. A pin with both accepts either.
public struct Pin: Sendable, Hashable {
    /// A GitHub repository, `owner/name[@tag][@sha256:digest]`
    public let repo: String?
    /// A config registry project, `org/project[@revision][@sha256:digest]`
    public let project: String?

    /// No pin: any config that the verifier's trust authorizes is accepted.
    /// The default verifier refuses it, since its trust is the whole public
    /// registry.
    public static let none = Pin()

    public init(repo: String) {
        self.repo = repo
        self.project = nil
    }

    public init(project: String) {
        self.repo = nil
        self.project = project
    }

    public init(repo: String, project: String) {
        self.repo = repo
        self.project = project
    }

    private init() {
        self.repo = nil
        self.project = nil
    }
}
