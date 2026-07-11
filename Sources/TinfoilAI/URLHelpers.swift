import Foundation

/// Helper functions for URL handling
internal enum URLHelpers {
    private static func hasSchemeWithoutAuthority(_ urlString: String) -> Bool {
        guard let separator = urlString.firstIndex(of: ":") else { return false }
        let candidate = urlString[..<separator]
        guard candidate.first?.isLetter == true,
              candidate.allSatisfy({ $0.isLetter || $0.isNumber || "+-.".contains($0) }) else {
            return false
        }

        let remainder = urlString[urlString.index(after: separator)...]
        let port = remainder.prefix(while: \.isNumber)
        let suffix = remainder.dropFirst(port.count)
        let hasValidPortSuffix = suffix.first.map { "/?#".contains($0) } ?? true
        let isHostPort = !port.isEmpty && hasValidPortSuffix
        return !isHostPort
    }

    /// Normalizes a URL string by adding https:// prefix if no protocol is specified
    static func normalizeURL(_ urlString: String) -> String {
        // Check if the URL already has a protocol
        if urlString.contains("://") || hasSchemeWithoutAuthority(urlString) {
            return urlString
        }
        // Add https:// prefix if no protocol is present
        return "https://\(urlString)"
    }
    
    /// Parses a URL string and returns its components
    /// - Parameter urlString: The URL string to parse (with or without protocol)
    /// - Returns: A tuple containing the URL, host, scheme, and optional port
    /// - Throws: An error if the URL is invalid
    static func parseURL(_ urlString: String) throws -> (url: URL, host: String, scheme: String, port: Int?) {
        let normalizedURL = normalizeURL(urlString)
        
        guard let url = URL(string: normalizedURL),
              let host = url.host else {
            throw NSError(domain: TinfoilConstants.urlHelpersErrorDomain,
                          code: TinfoilConstants.invalidURLErrorCode,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid URL: \(urlString)"])
        }
        
        let scheme = url.scheme?.lowercased() ?? "https"
        let port = url.port
        
        return (url: url, host: host, scheme: scheme, port: port)
    }

    /// Parses an HTTP API URL and requires the http or https scheme.
    static func parseHTTPURL(_ urlString: String) throws -> (url: URL, host: String, scheme: String, port: Int?) {
        let components = try parseURL(urlString)
        guard components.scheme == "http" || components.scheme == "https" else {
            throw NSError(domain: TinfoilConstants.urlHelpersErrorDomain,
                          code: TinfoilConstants.invalidURLErrorCode,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid HTTP(S) URL: \(urlString)"])
        }
        return components
    }
    
    /// Builds a host string with port if needed
    /// - Parameters:
    ///   - host: The hostname
    ///   - port: Optional port number
    /// - Returns: Host string with port appended if provided
    static func buildHostWithPort(host: String, port: Int?) -> String {
        return port.map { "\(host):\($0)" } ?? host
    }

    /// Extracts the origin (scheme://host:port) from a URL string for comparison
    /// - Parameter urlString: The URL string to extract origin from
    /// - Returns: The origin string (scheme://host:port), or empty string if invalid
    static func origin(from urlString: String) -> String {
        guard let components = try? parseURL(urlString) else { return "" }
        let hostWithPort = buildHostWithPort(host: components.host, port: components.port)
        return "\(components.scheme)://\(hostWithPort)"
    }

    /// Extracts the path and query string from a URL
    /// - Parameter url: The URL to extract path from
    /// - Returns: The path with query string if present (e.g., "/v1/chat?model=gpt-4")
    static func extractPath(from url: URL) -> String {
        var path = url.path
        if let query = url.query {
            path += "?\(query)"
        }
        return path
    }

    /// Header name for communicating the verified enclave URL to proxies
    static let enclaveURLHeaderName = "X-Tinfoil-Enclave-Url"

    /// Adds the proxy header to the headers dictionary if the baseURL and enclaveURL have different origins.
    /// This header tells the proxy where to forward the encrypted request.
    /// - Parameters:
    ///   - headers: The headers dictionary to modify
    ///   - baseURL: The URL where requests are sent (e.g., proxy server)
    ///   - enclaveURL: The URL of the verified enclave
    static func addProxyHeaderIfNeeded(to headers: inout [String: String], baseURL: String, enclaveURL: String?) {
        guard let enclaveURL = enclaveURL, !enclaveURL.isEmpty else { return }
        if origin(from: baseURL) != origin(from: enclaveURL) {
            headers[enclaveURLHeaderName] = enclaveURL
        }
    }
} 