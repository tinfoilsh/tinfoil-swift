import Foundation
import OpenAIKit
import AsyncHTTPClient
import NIOCore
import Logging

/// A secure wrapper for OpenAIKit.Client that uses certificate pinning
public class SecureOpenAIClient {
    private let client: OpenAIKit.Client
    private let secureClient: SecureHTTPClient
    
    public init(client: OpenAIKit.Client, secureClient: SecureHTTPClient) {
        self.client = client
        self.secureClient = secureClient
    }
    
    /// Creates a new secure OpenAI client with certificate pinning
    public static func create(
        apiKey: String,
        enclaveURL: String,
        expectedFingerprint: String,
        eventLoopGroup: EventLoopGroup,
        logger: Logger
    ) throws -> SecureOpenAIClient {
        // Create the secure HTTP client
        let secureHTTPClient = try SecureHTTPClient.create(
            eventLoopGroup: eventLoopGroup,
            expectedFingerprint: expectedFingerprint,
            logger: logger
        ) { tlsConfig in
            tlsConfig.verifySignatureAlgorithms = [.ecdsaSecp384R1Sha384]
            tlsConfig.trustRoots = .default
        }
        
        // Create the OpenAI client
        let openAIClient = OpenAIKit.Client(
            httpClient: secureHTTPClient.underlyingClient,
            configuration: .init(
                apiKey: apiKey,
                api: .init(scheme: .https, host: enclaveURL)
            )
        )
        
        // Create and return the secure wrapper
        return SecureOpenAIClient(
            client: openAIClient,
            secureClient: secureHTTPClient
        )
    }
    
    /// Forwards requests to the underlying OpenAIKit.Client
    public var underlyingClient: OpenAIKit.Client {
        return self.client
    }
    
    /// Shuts down the client
    public func shutdown() throws {
        try self.secureClient.shutdown()
    }
} 