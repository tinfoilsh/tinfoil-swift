import Foundation
import EHBP

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A response whose body is still streaming, with the session recovery token
/// that can decrypt it again later, without the live session.
public struct RecoverableResponse: Sendable {
    /// The response's status and headers
    public let response: HTTPURLResponse
    /// With the `Ehbp-Response-Nonce` header of a stored copy of this
    /// response, decrypts it through `SessionRecoveryToken.makeResponseDecryptor`.
    /// Nil when the response isn't sealed: the request had no body, or an
    /// intermediary answered with an unencrypted error.
    ///
    /// It is key material for this one response: store it protected, and
    /// delete it once the response is fully read or a newer request replaces
    /// it.
    public let recoveryToken: SessionRecoveryToken?
    /// The decrypted body, chunk by chunk as it arrives. To stop early, cancel
    /// the task iterating it or release the response: breaking out of the
    /// loop alone leaves the transfer running until the response is released.
    public let body: AsyncThrowingStream<Data, Error>
}
