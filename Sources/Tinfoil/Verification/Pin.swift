/// What each verification is checked against, as `Trust.pin()` derives it.
/// `repo` and `project` are separate namespaces with unrelated owners, so
/// neither is satisfied by the other's evidence: a repository only by its
/// signed release, a project only by a registry deployment. A pin with both
/// accepts either.
struct Pin: Sendable, Hashable {
    /// A GitHub repository, `owner/name[@tag][@sha256:digest]`
    let repo: String?
    /// A config registry project, `org/project[@revision][@sha256:digest]`
    let project: String?

    /// No pin: any config that the verifier's trust authorizes is accepted.
    /// The default verifier refuses it, since its trust is the whole public
    /// registry.
    static let none = Pin()

    init(repo: String) {
        self.repo = repo
        self.project = nil
    }

    init(project: String) {
        self.repo = nil
        self.project = project
    }

    init(repo: String, project: String) {
        self.repo = repo
        self.project = project
    }

    private init() {
        self.repo = nil
        self.project = nil
    }
}
