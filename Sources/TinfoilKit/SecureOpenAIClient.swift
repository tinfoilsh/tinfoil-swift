import Foundation
import OpenAIKit

/// A secure wrapper for OpenAIKit.Client that uses certificate pinning
public class SecureOpenAIClient {
    private let client: OpenAIKit.Client
    private let urlSession: URLSession
    
    private init(client: OpenAIKit.Client, urlSession: URLSession) {
        self.client = client
        self.urlSession = urlSession
    }
    
    /// Creates a new secure OpenAI client with certificate pinning
    public static func create(
        apiKey: String,
        enclaveURL: String,
        expectedFingerprint: String
    ) throws -> SecureOpenAIClient {
        // Create a logger
        let logger = PinningLogger(label: "com.tinfoil.secure-urlsession")
        
        // Create the secure URLSession with certificate pinning
        let urlSession = SecureURLSessionFactory.createSession(
            expectedFingerprint: expectedFingerprint,
            logger: logger
        )
        
        // Parse the URL components from the enclave URL
        var scheme = "https"
        var host = enclaveURL
        var port: Int? = nil
        var path: String? = nil
        
        // Use URLComponents for more robust URL parsing
        if let url = URL(string: enclaveURL), let components = URLComponents(url: url, resolvingAgainstBaseURL: false) {
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
                
                // Verify that path is not the same as host (which would be incorrect)
                if path == host || path == components.host {
                    logger.debug("Path appears to be the same as host, ignoring path")
                    path = nil
                } else {
                    logger.debug("Found path in URL: \(path ?? "nil")")
                }
            } else {
                logger.debug("No path found in URL, will use default 'v1'")
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
                
                // Verify that path is not the same as host (which would be incorrect)
                if path == host {
                    logger.debug("Manual parsing - path appears to be the same as host, ignoring path")
                    path = nil
                } else {
                    logger.debug("Manual parsing - found path: \(path ?? "nil")")
                }
            } else {
                logger.debug("Manual parsing - no path found, will use default 'v1'")
            }
            
            // Extract port if present
            if let portIndex = host.firstIndex(of: ":") {
                let portString = String(host[host.index(after: portIndex)...])
                port = Int(portString)
                host = String(host[..<portIndex])
            }
        }
        
        logger.debug("Parsed URL - scheme: \(scheme), host: \(host), port: \(port?.description ?? "default"), path: \(path ?? "nil")")
        
        // Create custom API configuration with the parsed URL components
        let apiScheme: OpenAIKit.API.Scheme = scheme == "https" ? .https : .http
        
        // Include port in host if specified
        let finalHost: String
        if let port = port {
            finalHost = "\(host):\(port)"
        } else {
            finalHost = host
        }
        
        // Ensure we're using a valid path prefix
        var pathPrefix: String
        if let extractedPath = path {
            // Final safety check to ensure path is not the same as host
            if extractedPath == host || extractedPath == finalHost {
                logger.debug("Final check - path appears to be the same as host, using default path")
                // Try empty path first as some APIs expect this
                pathPrefix = ""
            } else {
                pathPrefix = extractedPath
            }
        } else {
            // For OpenAI-compatible APIs, the default is often an empty string or "v1"
            // Try empty string first
            pathPrefix = ""
        }
        
        // Log a note about the path prefix choice
        logger.debug("Using pathPrefix: \"\(pathPrefix)\" (empty string if shown blank)")
        
        // Create API configuration
        let api = OpenAIKit.API(
            scheme: apiScheme,
            host: finalHost,
            pathPrefix: pathPrefix
        )
        
        // Create client configuration with custom API
        let configuration = OpenAIKit.Configuration(
            apiKey: apiKey,
            organization: nil,
            api: api
        )
        
        logger.debug("Creating OpenAIKit.Client with API configuration:")
        logger.debug("- Scheme: \(scheme)")  // Use the original scheme string
        logger.debug("- Host: \(finalHost)")
        logger.debug("- Path prefix: \(pathPrefix)")
        logger.debug("- API key length: \(apiKey.count) characters")
        
        // Log the expected API base URL for debugging
        let apiBaseURLString: String
        if pathPrefix.isEmpty {
            apiBaseURLString = "\(scheme)://\(finalHost)"
            logger.debug("- Expected API base URL: \(apiBaseURLString) (no path prefix)")
        } else {
            apiBaseURLString = "\(scheme)://\(finalHost)/\(pathPrefix)"
            logger.debug("- Expected API base URL: \(apiBaseURLString)")
        }
        
        // Additional verification to ensure we have a valid URL
        guard URL(string: apiBaseURLString) != nil else {
            logger.error("Invalid URL generated: \(apiBaseURLString)")
            throw NSError(domain: "com.tinfoil.secure-urlsession", 
                          code: 1001, 
                          userInfo: [NSLocalizedDescriptionKey: "Invalid URL generated: \(apiBaseURLString)"])
        }
        
        let openAIClient = OpenAIKit.Client(session: urlSession, configuration: configuration)
        
        // Create and return the secure wrapper
        return SecureOpenAIClient(
            client: openAIClient,
            urlSession: urlSession
        )
    }
    
    /// Forwards requests to the underlying OpenAIKit.Client
    public var underlyingClient: OpenAIKit.Client {
        return self.client
    }
    
    /// Shuts down the client
    public func shutdown() {
        // Cancel all tasks and invalidate the URLSession
        self.urlSession.invalidateAndCancel()
    }
    
    /// Test the connection by fetching models (for debugging purposes)
    public func testConnection() async -> Result<String, Error> {
        do {
            // Try to make a simple request to list models
            let models = try await self.client.models.list()
            return .success("Successfully connected. Found \(models.count) models.")
        } catch {
            return .failure(error)
        }
    }
} 