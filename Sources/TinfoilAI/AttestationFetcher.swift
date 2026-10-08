import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Fetches attestation material with the app's own networking, so system
/// proxies and task cancellation apply. Its limits match the Go SDK's fetch:
/// HTTPS only, every redirect included; a 30 second timeout; a 32 MiB cap on
/// the body; and a session of its own for every fetch, because a pooled
/// connection may still reach a replica that is draining after a cutover.
struct AttestationFetcher: Sendable {
    static let sdkNameHeader = "Tinfoil-SDK"
    static let sdkVersionHeader = "Tinfoil-SDK-Version"
    static let maximumRedirects = 10

    private let timeout: TimeInterval
    private let maximumBodyBytes: Int
    private let makeConfiguration: @Sendable () -> URLSessionConfiguration

    /// - Parameter makeConfiguration: Builds each fetch's session
    ///   configuration; tests substitute protocol classes.
    init(
        timeout: TimeInterval = 30,
        maximumBodyBytes: Int = 32 << 20,
        makeConfiguration: @escaping @Sendable () -> URLSessionConfiguration = { .ephemeral }
    ) {
        self.timeout = timeout
        self.maximumBodyBytes = maximumBodyBytes
        self.makeConfiguration = makeConfiguration
    }

    /// Returns the body of a GET of url, which must be HTTPS.
    func fetch(_ url: URL) async throws -> Data {
        guard url.scheme?.lowercased() == "https" else {
            throw TinfoilError.invalidConfiguration("attestation must be fetched over HTTPS, not \(url.absoluteString)")
        }
        var request = URLRequest(url: url)
        request.setValue(TinfoilConstants.sdkName, forHTTPHeaderField: Self.sdkNameHeader)
        request.setValue(TinfoilConstants.sdkVersion, forHTTPHeaderField: Self.sdkVersionHeader)

        let configuration = makeConfiguration()
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        configuration.urlCache = nil
        configuration.httpShouldSetCookies = false
        let redirects = RedirectPolicy(maximumRedirects: Self.maximumRedirects)
        let session = URLSession(configuration: configuration, delegate: redirects, delegateQueue: nil)
        defer { session.invalidateAndCancel() }

        do {
            let (bytes, response) = try await session.bytes(for: request)
            // A refused redirect completes with the redirect response itself.
            if let refusal = redirects.refusal {
                throw TinfoilError.fetchError(refusal)
            }
            guard let response = response as? HTTPURLResponse else {
                throw TinfoilError.fetchError("GET \(url.absoluteString) returned a response that is not HTTP")
            }
            guard (200...299).contains(response.statusCode) else {
                throw TinfoilError.fetchError(
                    "HTTP GET \(url.absoluteString): \(response.statusCode) \(HTTPURLResponse.localizedString(forStatusCode: response.statusCode))",
                    status: response.statusCode
                )
            }
            if response.expectedContentLength > Int64(maximumBodyBytes) {
                throw tooLarge(url)
            }
            var body = Data()
            for try await byte in bytes {
                body.append(byte)
                if body.count > maximumBodyBytes {
                    throw tooLarge(url)
                }
            }
            return body
        } catch let error as TinfoilError {
            throw error
        } catch {
            if Task.isCancelled {
                throw CancellationError()
            }
            let urlError = error as? URLError
            if urlError?.code == .timedOut {
                throw TinfoilError.fetchError("GET \(url.absoluteString) timed out after \(Int(timeout)) seconds", urlError: urlError)
            }
            throw TinfoilError.fetchError("GET \(url.absoluteString): \(error.localizedDescription)", urlError: urlError)
        }
    }

    private func tooLarge(_ url: URL) -> TinfoilError {
        .fetchError("response from \(url.absoluteString) exceeds \(maximumBodyBytes) bytes")
    }
}

/// Follows HTTPS redirects up to a limit and refuses any other, recording why
/// so the fetch can report it instead of the redirect response.
private final class RedirectPolicy: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let maximumRedirects: Int
    private let lock = NSLock()
    private var followed = 0
    private var _refusal: String?

    init(maximumRedirects: Int) {
        self.maximumRedirects = maximumRedirects
    }

    var refusal: String? {
        lock.lock()
        defer { lock.unlock() }
        return _refusal
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        lock.lock()
        if request.url?.scheme?.lowercased() != "https" {
            _refusal = "refusing redirect to non-HTTPS URL \(request.url?.absoluteString ?? "(none)")"
        } else if followed >= maximumRedirects {
            _refusal = "stopped after \(maximumRedirects) redirects"
        } else {
            followed += 1
        }
        let refused = _refusal != nil
        lock.unlock()
        completionHandler(refused ? nil : request)
    }
}
