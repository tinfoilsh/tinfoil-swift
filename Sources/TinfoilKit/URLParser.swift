import Foundation

/// A utility class for parsing OpenAI API URLs into their components
public struct URLParser {
    /// Represents the components of a parsed OpenAI API URL
    public struct URLComponents {
        public let scheme: String
        public let host: String
        public let port: Int?
        public let path: String?
        
        public var finalHost: String {
            if let port = port {
                return "\(host):\(port)"
            }
            return host
        }
        
        public var pathPrefix: String {
            guard let extractedPath = path else {
                return ""
            }
            
            // Final safety check to ensure path is not the same as host or finalHost
            if extractedPath == host || extractedPath == finalHost {
                return ""
            }
            
            return extractedPath
        }
    }
    
    /// Parse an OpenAI API URL into its components
    /// - Parameters:
    ///   - url: The URL string to parse
    /// - Returns: The parsed URL components
    public static func parse(url: String) -> URLComponents {
        var scheme = "https"
        var host = url
        var port: Int? = nil
        var path: String? = nil
        
        // Try using URLComponents for robust parsing
        if let url = URL(string: url), let components = Foundation.URLComponents(url: url, resolvingAgainstBaseURL: false) {
            if let urlScheme = components.scheme {
                scheme = urlScheme
            }
            
            if let urlHost = components.host {
                host = urlHost
            }
            
            port = components.port
            
            // Extract path (remove leading slash for pathPrefix)
            if !components.path.isEmpty && components.path != "/" {
                let urlPath = components.path
                path = urlPath.hasPrefix("/") ? String(urlPath.dropFirst()) : urlPath
                
                // Verify that path is not the same as host
                if path == host || path == components.host {
                    path = nil
                }
            }
        } else {
            // Fallback to manual parsing if URLComponents fails
            if host.hasPrefix("https://") {
                host = String(host.dropFirst(8))
                scheme = "https"
            } else if host.hasPrefix("http://") {
                host = String(host.dropFirst(7))
                scheme = "http"
            }
            
            // Extract path if present, and separate it from host
            if let pathIndex = host.firstIndex(of: "/") {
                let fullPath = String(host[pathIndex...])
                host = String(host[..<pathIndex])
                
                // Remove leading slash for pathPrefix
                path = fullPath.hasPrefix("/") ? String(fullPath.dropFirst()) : fullPath
                
                // Verify that path is not the same as host
                if path == host {
                    path = nil
                }
            }
            
            // Extract port if present
            if let portIndex = host.firstIndex(of: ":") {
                let portString = String(host[host.index(after: portIndex)...])
                port = Int(portString)
                host = String(host[..<portIndex])
            }
        }
        
        return URLComponents(scheme: scheme, host: host, port: port, path: path)
    }
} 