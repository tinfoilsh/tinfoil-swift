import Foundation
import OpenAIKit
import AsyncHTTPClient
import NIOCore
import NIOPosix
import NIOSSL
import NIOHTTP1
import Logging
import CryptoKit

/// Main entry point for the Tinfoil secure AI client library
public final class TinfoilAI {
    public let client: OpenAIKit.Client
    private let secureOpenAIClient: SecureOpenAIClient?
    private let eventLoopGroup: EventLoopGroup?
    
    /// Creates a new secure OpenAI client
    /// - Parameters:
    ///   - apiKey: Optional API key. If not provided, will be read from OPENAI_API_KEY environment variable
    ///   - githubOrg: GitHub organization name for verification
    ///   - githubRepo: GitHub repository name for verification
    ///   - enclaveURL: URL for the enclave attestation endpoint
    public init(
        apiKey: String? = nil,
        githubOrg: String,
        githubRepo: String,
        enclaveURL: String
    ) async throws {
        // Get API key from parameter or environment
        let finalApiKey = apiKey ?? ProcessInfo.processInfo.environment["OPENAI_API_KEY"]
        guard let finalApiKey = finalApiKey else {
            throw TinfoilError.missingAPIKey
        }
        
        // First verify the enclave
        let verifier = SecureClient(
            githubOrg: githubOrg,
            githubRepo: githubRepo,
            enclaveURL: enclaveURL,
            callbacks: VerificationCallbacks()
        )
        
        let verificationResult = try await verifier.verify()
        
        // Create event loop group
        self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let logger = Logger(label: "com.tinfoil.client")
        
        // Create secure OpenAI client with certificate fingerprint verification
        let secureClient = try SecureOpenAIClient.create(
            apiKey: finalApiKey,
            enclaveURL: enclaveURL,
            expectedFingerprint: verificationResult.certFingerprint,
            eventLoopGroup: self.eventLoopGroup!,
            logger: logger
        )
        
        self.secureOpenAIClient = secureClient
        self.client = secureClient.underlyingClient
    }
    
    deinit {
        // Clean up resources
        try? self.secureOpenAIClient?.shutdown()
        try? self.eventLoopGroup?.syncShutdownGracefully()
    }
}

/// Errors that can occur when using the Tinfoil client
public enum TinfoilError: Error {
    case missingAPIKey
    case invalidConfiguration(String)
} 