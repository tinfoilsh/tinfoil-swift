import Foundation

/// A handle on one attested enclave, matching tinfoil-go's `enclave.Handle`.
/// Pass one to `TinfoilAI.create` to configure how the client's enclave is
/// verified.
///
/// Each `verify()` is one run. A run fetches an enclave's attestation document
/// and has tinfoil-go verify it, retrying a failed attempt once. Before the
/// first run picks an enclave, it may try several of Tinfoil's routers. Every
/// enclave whose evidence verifies is passed to `onEnclaveVerified`, which can
/// reject it, and the run's final result goes to `onVerificationResult`. The
/// latest successful result stays in `verification`.
public actor EnclaveHandle {
    private let enclave: String?
    private let repo: String
    private let attestationRelay: String?
    private let attestor: Attestor
    private let onVerificationResult: VerificationResultCallback?
    private let send: PinnedTLS.Send
    private let now: @Sendable () -> Date
    /// The configured enclave, or the router discovery picked on the first
    /// verification; later verifications stay with it.
    private var selectedEnclave: String?
    /// The verification in progress, shared by every caller that asks while
    /// it runs
    private var inFlight: Task<Verification, Error>?

    /// The latest successful verification, or nil before the first. It may
    /// have expired; `verifyIfNeeded()` returns one that has not.
    public private(set) var verification: Verification?

    /// The verified enclave's base URL, or nil before the first verification.
    /// Relative URLs passed to `data(for:)` resolve against it.
    public var enclaveURL: URL? {
        verification.flatMap { URL(string: "https://\($0.enclaveHost)") }
    }

    /// - Parameters:
    ///   - enclave: Host of the enclave to verify, such as
    ///     "inference.tinfoil.sh". When nil, the first verification picks one
    ///     of Tinfoil's routers, which requires the default repo.
    ///   - repo: The trusted owner/name[@tag][@sha256:digest] the enclave's
    ///     code must come from.
    ///   - attestationRelay: Host, with an optional port, that forwards
    ///     attestation requests to the enclave. Without an enclave, a relay is
    ///     asked for the fallback router rather than running discovery.
    ///   - policy: Checks beyond the defaults.
    ///   - onEnclaveVerified: Called each time an enclave's evidence verifies,
    ///     before it is used; throw to reject the enclave. This callback can
    ///     be used to define additional user-specific policies that further
    ///     restrict which enclaves are accepted.
    ///   - onVerificationResult: Called with each `verify()` run's final result
    ///     (i.e. after potentially several enclaves are tried); this callback
    ///     only observes the end verification result and cannot synchronously
    ///     reject enclaves.
    public init(
        enclave: String? = nil,
        repo: String = TinfoilConstants.defaultGithubRepo,
        attestationRelay: String? = nil,
        policy: VerificationPolicy = VerificationPolicy(),
        onEnclaveVerified: EnclaveVerifiedCallback? = nil,
        onVerificationResult: VerificationResultCallback? = nil
    ) throws {
        try self.init(
            enclave: enclave,
            repo: repo,
            attestationRelay: attestationRelay,
            attestor: Attestor(verifier: GoAttestationVerifier(policy: policy), onEnclaveVerified: onEnclaveVerified),
            onVerificationResult: onVerificationResult
        )
    }

    init(
        enclave: String?,
        repo: String,
        attestationRelay: String?,
        attestor: Attestor,
        onVerificationResult: VerificationResultCallback? = nil,
        send: @escaping PinnedTLS.Send = { try await PinnedTLS.send($0, expecting: $1) },
        now: @escaping @Sendable () -> Date = { Date() }
    ) throws {
        guard enclave != nil || repo == TinfoilConstants.defaultGithubRepo else {
            throw TinfoilError.invalidConfiguration(
                "an enclave is required to verify against \(repo); only Tinfoil's routers are discovered"
            )
        }
        self.enclave = enclave
        self.repo = repo
        self.attestationRelay = attestationRelay
        self.attestor = attestor
        self.onVerificationResult = onVerificationResult
        self.send = send
        self.now = now
    }

    /// Verifies the enclave against fresh evidence and returns the result.
    /// Calls made while a verification runs share it, so concurrent first
    /// calls discover a single router. Cancelling a call ends only its own
    /// wait; the shared verification still completes. To reuse a verification
    /// that is still fresh, use `verifyIfNeeded()`.
    public func verify() async throws -> Verification {
        let task: Task<Verification, Error>
        if let inFlight {
            task = inFlight
        } else {
            task = Task {
                defer { self.inFlight = nil }
                // Reported here, once per run, however many callers share it.
                do {
                    let verified = try await self.verifyNow()
                    self.onVerificationResult?(.success(verified))
                    return verified
                } catch let error as TinfoilError {
                    self.onVerificationResult?(.failure(error))
                    throw error
                }
            }
            inFlight = task
        }
        return try await waitForSharedTask(task)
    }

    private func verifyNow() async throws -> Verification {
        let verified: Verification
        if let host = selectedEnclave ?? enclave {
            verified = try await attestor.attest(host: host, relay: attestationRelay, repo: repo)
        } else if let attestationRelay {
            verified = try await attestor.attest(
                host: TinfoilConstants.fallbackEnclave,
                relay: attestationRelay,
                repo: repo
            )
        } else {
            verified = try await attestor.attestDefaultRouter()
        }
        selectedEnclave = verified.enclaveHost
        verification = verified
        return verified
    }

    /// Loads a request from the enclave over TLS pinned to its attested key,
    /// as `URLSession.data(for:)` does. A URL without a host resolves against
    /// the verified enclave; an absolute URL must be HTTPS to that enclave, and
    /// so must any redirect, so credentials never leave it. The request uses the
    /// current verification, verifying first if there is none or it has
    /// expired. If the enclave presents a key the attestation does not endorse
    /// before the request was sent, the handle verifies again and retries
    /// once; otherwise, or if it happens again, it fails with
    /// `TinfoilError.attestationError`.
    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var attempt = 0
        while true {
            let verification = try await verifyIfNeeded()
            var pinned = request
            pinned.url = try Self.resolve(request.url, against: verification)
            do {
                return try await send(pinned, verification.tlsPublicKeyFingerprint)
            } catch let rejection as PinnedTLS.Rejection {
                attempt += 1
                // Replaying is safe only if the request never left: a rejection
                // on a later connection, as after a redirect, may follow one
                // that reached the enclave.
                guard attempt < 2, !rejection.requestMayHaveBeenSent else {
                    throw TinfoilError.attestationError(rejection.description)
                }
                // The enclave may have rotated its key since it was verified.
                _ = try await verify()
            }
        }
    }

    /// Loads a URL from the enclave, as `URLSession.data(from:)` does. See
    /// `data(for:)`.
    public func data(from url: URL) async throws -> (Data, HTTPURLResponse) {
        try await data(for: URLRequest(url: url))
    }

    /// Verifies the enclave only when there is no verification yet or the
    /// latest has reached its `freshnessExpiresAt`, as requests through the
    /// handle do, and otherwise returns the latest. Call it to warm up or
    /// check the handle without attesting on every call, rather than
    /// comparing `freshnessExpiresAt` with the time yourself.
    public func verifyIfNeeded() async throws -> Verification {
        if let verification, now() < verification.freshnessExpiresAt {
            return verification
        }
        let verified = try await verify()
        guard now() < verified.freshnessExpiresAt else {
            throw TinfoilError.attestationError("verification of \(verified.enclaveHost) is already past its freshness deadline")
        }
        return verified
    }

    /// The URL to request: a URL without a host resolves against the
    /// enclave, and the result, however it was written, must be HTTPS on the
    /// enclave's origin.
    private static func resolve(_ url: URL?, against verification: Verification) throws -> URL {
        guard let url else {
            throw TinfoilError.invalidConfiguration("the request has no URL")
        }
        guard let base = URL(string: "https://\(verification.enclaveHost)") else {
            throw TinfoilError.invalidConfiguration("cannot form a URL for \(verification.enclaveHost)")
        }
        let target = url.host == nil ? URL(string: url.relativeString, relativeTo: base)?.absoluteURL : url
        // A URL with a scheme but no "//", such as "https:other.example/x",
        // parses with a nil host and "other.example/x" as its path, so it
        // takes the relative branch above. Having a scheme makes it an
        // absolute reference (RFC 3986 §5.2), so resolving it against the
        // enclave returns it unchanged. URLSession is more lenient and reads
        // it as "https://other.example/x", connecting to other.example.
        // Requiring a host refuses it explicitly, rather than relying on the
        // origin check below failing because URLHelpers.origin cannot parse it.
        guard let target, target.host != nil, target.scheme?.lowercased() == "https" else {
            throw TinfoilError.invalidConfiguration("requests to the enclave must be HTTPS URLs with a host, not \(url.absoluteString)")
        }
        let enclave = URLHelpers.origin(from: base.absoluteString)
        guard !enclave.isEmpty, URLHelpers.origin(from: target.absoluteString) == enclave else {
            throw TinfoilError.invalidConfiguration(
                "requests go only to the verified enclave \(verification.enclaveHost), not \(target.host ?? target.absoluteString)"
            )
        }
        return target
    }
}
