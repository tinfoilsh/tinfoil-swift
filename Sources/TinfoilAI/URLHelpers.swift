import Foundation

/// Helper functions for URL handling
internal enum URLHelpers {
    /// Normalizes a URL string by adding https:// prefix if no protocol is specified
    static func normalizeURL(_ urlString: String) -> String {
        // Check if the URL already has a protocol
        if urlString.contains("://") {
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
            throw NSError(domain: "sh.tinfoil.url-helpers",
                          code: 1001,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid URL: \(urlString)"])
        }
        
        let scheme = url.scheme ?? "https"
        let port = url.port
        
        return (url: url, host: host, scheme: scheme, port: port)
    }
    
    /// Builds a host string with port if needed
    /// - Parameters:
    ///   - host: The hostname
    ///   - port: Optional port number
    /// - Returns: Host string with port appended if provided
    static func buildHostWithPort(host: String, port: Int?) -> String {
        return port != nil ? "\(host):\(port!)" : host
    }
} 