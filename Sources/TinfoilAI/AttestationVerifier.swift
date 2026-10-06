import Foundation

/// The tinfoil-go verifier, which owns every trust decision about an
/// attestation document. It performs no I/O: the caller fetches each document
/// itself, from `attestationURL` with a nonce from `newNonce`, and passes the
/// bytes to `verify`. Code built on it depends on this protocol rather than
/// on the framework, so it can be tested with a stand-in.
protocol AttestationVerifier: Sendable {
    /// A fresh random challenge for one attestation fetch. The same bytes go
    /// to `attestationURL` and `verify`, and are never reused.
    func newNonce() -> Data

    /// The HTTPS URL to GET host's attestation document from with nonce,
    /// through relay when it is not nil. Both are a host with an optional
    /// port, not a URL.
    func attestationURL(host: String, relay: String?, nonce: Data) throws -> URL

    /// Appraises document, fetched from enclaveHost with nonce, against repo,
    /// a trusted owner/name[@tag][@sha256:digest] reference. Fails with a
    /// `TinfoilError`, including for a result already past its freshness
    /// deadline.
    func verify(document: Data, nonce: Data, repo: String, enclaveHost: String) throws -> Verification
}
