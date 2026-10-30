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

    /// The host lowercased, with an IPv6 literal in its canonical text form
    /// (RFC 5952), so differently written forms of one address compare
    /// equal. An IPv6 zone identifier keeps its case, since zones that differ
    /// only in case are distinct.
    static func canonicalHost(_ host: String) -> String {
        let bare = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        let parts = bare.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)
        var address = in6_addr()
        guard bare.contains(":"), inet_pton(AF_INET6, String(parts[0]), &address) == 1 else {
            return host.lowercased()
        }
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &address, &text, socklen_t(text.count)) != nil else {
            return host.lowercased()
        }
        let canonical = String(cString: text)
        return parts.count == 2 ? "\(canonical)%\(parts[1])" : canonical
    }

    /// Whether the URL's host, as written, is `localhost` or a loopback IP
    /// address: an IPv4 address in 127.0.0.0/8, `::1`, or an IPv4-mapped
    /// IPv6 address in 127.0.0.0/8. No name is resolved, so DNS can't make a
    /// remote host pass. The host is read percent-encoded, so an encoded name
    /// such as `%6cocalhost` doesn't count, and IPv4 must be four decimal
    /// octets without leading zeros, since a resolver may read `0127.0.0.1`
    /// as octal and `127.1` as shorthand. A trailing dot is not stripped, so
    /// `localhost.` and `127.0.0.1.` don't count either.
    static func hasLoopbackHost(_ url: URL) -> Bool {
        guard let host = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedHost else {
            return false
        }
        if host.hasPrefix("["), host.hasSuffix("]") {
            // A zone identifier follows its percent-encoded "%" as "%25".
            let parts = host.dropFirst().dropLast().split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 1 || (parts[1].hasPrefix("25") && parts[1].count > 2) else { return false }
            return isLoopbackIPv6(String(parts[0]))
        }
        return host.lowercased() == "localhost" || ipv4Octets(host)?.first == 127
    }

    /// The octets of an IPv4 address written as four decimal octets without
    /// leading zeros, or nil for any other form.
    private static func ipv4Octets(_ text: some StringProtocol) -> [UInt8]? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [UInt8] = []
        for part in parts {
            guard (1...3).contains(part.count),
                  part.allSatisfy({ $0.isASCII && $0.isNumber }),
                  part.count == 1 || part.first != "0",
                  let octet = UInt8(part) else {
                return nil
            }
            octets.append(octet)
        }
        return octets
    }

    /// Whether an IPv6 address, without brackets or zone, is `::1` or an
    /// IPv4-mapped address in 127.0.0.0/8.
    private static func isLoopbackIPv6(_ text: String) -> Bool {
        // inet_pton accepts leading zeros in an embedded IPv4 address.
        if text.contains("."), let tail = text.split(separator: ":").last, ipv4Octets(tail) == nil {
            return false
        }
        var address = in6_addr()
        guard inet_pton(AF_INET6, text, &address) == 1 else { return false }
        let bytes = withUnsafeBytes(of: &address) { Array($0) }
        let loopback = bytes[..<15].allSatisfy { $0 == 0 } && bytes[15] == 1
        let mapped = bytes[..<10].allSatisfy { $0 == 0 } && bytes[10] == 0xff && bytes[11] == 0xff && bytes[12] == 127
        return loopback || mapped
    }

    /// Extracts the origin (scheme://host:port) from a URL string for comparison
    /// - Parameter urlString: The URL string to extract origin from
    /// - Returns: The origin string (scheme://host:port), or empty string if invalid
    static func origin(from urlString: String) -> String {
        guard let components = try? parseURL(urlString) else { return "" }
        let scheme = components.scheme.lowercased()
        var host = canonicalHost(components.host)
        // DNS permits an absolute name to end in a dot. Remove only that
        // suffix; a leading dot is not an equivalent host identity.
        while host.hasSuffix(".") {
            host.removeLast()
        }
        if host.contains(":"), !host.hasPrefix("[") {
            host = "[\(host)]"
        }
        let effectivePort = components.port ?? (scheme == "https" ? 443 : 80)
        return "\(scheme)://\(host):\(effectivePort)"
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
