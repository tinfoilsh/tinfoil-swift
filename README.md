# Tinfoil Swift

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20|%20macOS-blue.svg)](https://developer.apple.com)
[![Tests](https://github.com/tinfoilsh/tinfoil-swift/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-swift/actions/workflows/test.yml)
[![Docs](https://img.shields.io/badge/Docs-Swift%20SDK-blue.svg)](https://docs.tinfoil.sh/sdk/swift-sdk)

A secure Swift SDK for communicating with AI models running in Tinfoil's confidential computing enclaves. This SDK configures the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI) with additional security features including automatic enclave attestation verification and certificate pinning for direct-to-enclave encrypted communication.

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/tinfoilsh/tinfoil-swift.git", branch: "main")
]
```

Or in Xcode:

1. Go to File > Add Packages...
2. Enter the repository URL: `https://github.com/tinfoilsh/tinfoil-swift.git`
3. Select the branch or version you want to use
4. Click "Add Package"

The OpenAI SDK dependency will be automatically included.

## Quick Start

```swift
import TinfoilAI
import OpenAI

// Create a secure OpenAI client
// This automatically:
// - Fetches an available router from Tinfoil's network
// - Verifies the enclave is running genuine Tinfoil code
// - Sets up certificate pinning for all requests
let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY" // Optional, uses TINFOIL_API_KEY env var if not provided
)

// Use the client exactly like the OpenAI SDK
let chatQuery = ChatQuery(
    messages: [
        .user(.init(content: .string("Hello, world!")))
    ],
    model: "model-name"
)

let response = try await client.chats(query: chatQuery)
print(response.choices.first?.message.content ?? "No response")
```


## Key Features

- **Automatic Router Selection**: Dynamically selects from available Tinfoil routers
- **Enclave Verification**: Verifies code integrity via GitHub and Sigstore
- **Remote Attestation**: Validates the enclave runtime environment (AMD SEV-SNP / Intel TDX)
- **Certificate Pinning**: Ensures direct-to-enclave encrypted communication
- **OpenAI Compatible**: Drop-in replacement for OpenAI SDK

## Advanced Features

### Streaming Responses

Stream responses in real-time as they're generated:

```swift
let client = try await TinfoilAI.create()

let chatQuery = ChatQuery(
    messages: [.user(.init(content: .string("Tell me a story")))],
    model: "model-name"
)

// Stream the response
for try await chunk in client.chatsStream(query: chatQuery) {
    if let delta = chunk.choices.first?.delta.content {
        print(delta, terminator: "")
    }
}
```

### Security Architecture

Tinfoil Swift combines **remote attestation** and **certificate pinning** to ensure your data only reaches verified enclave code. During setup, the SDK requests an attestation report that cryptographically proves the exact code running in the enclave and includes the enclave's TLS public key fingerprint. On every API request, the SDK validates the server's TLS certificate matches this attested fingerprint. This creates a cryptographic chain from GitHub source code → attestation → TLS connection, preventing man-in-the-middle attacks even if DNS or router selection is compromised.

#### Verification Callback

You can receive the verification document through an optional callback:

```swift
let verificationCallback: VerificationCallback = { verificationDocument in
    if let doc = verificationDocument {
        print("✅ Attestation verification successful")
        print("Code fingerprint: \(doc.codeFingerprint)")
        print("Enclave fingerprint: \(doc.enclaveFingerprint)")
        print("Security verified: \(doc.securityVerified)")
        print("All steps succeeded: \(doc.allStepsSucceeded)")
    }
}

let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY",
    onVerification: verificationCallback
)
```

## Prompt Cache Scoping

The inference router partitions prompt-prefix caches using both the authenticated API identity and `user_cache_secret`. Cache reuse requires the same identity, secret, model, and matching prompt prefix. Changing the identity or secret selects a different cache namespace, so those requests do not share cache entries or cache-hit timing.

`user_cache_secret` is sensitive application data used only for cache partitioning. It is not an API credential or encryption key. Do not log or expose it unnecessarily: a caller who can send requests with the same API identity and secret joins that cache namespace and can observe its cache-hit timing. The SDK adds it to eligible request bodies before they are protected for transport to the verified enclave, and the router removes it before forwarding the request to the model.

By default, the SDK generates a random secret and persists it at `~/.tinfoil/user_cache_secret`, requesting mode `0600` where supported. Tinfoil SDKs using the same home directory reuse this value. This default is suitable for a single-user application, but it does not separate end users who share one application process or home directory. You can control the scope explicitly:

```swift
// Pin a stable, non-empty, opaque secret for this client.
let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY",
    userCacheSecret: secret
)

// Or provision it via the environment
//   TINFOIL_USER_CACHE_SECRET=<secret>   use this value

// Multi-user services should scope every request to its end user.
// A non-empty string field set here wins over the client-level secret:
let query = ChatQuery(
    messages: [.user(.init(content: .string("Hello!")))],
    model: "model-name",
    extraBody: ["user_cache_secret": .string(perUserSecret)]
)
```

Resolution order is a non-empty per-request string, a non-empty client value, a non-empty `TINFOIL_USER_CACHE_SECRET`, then the generated default. Empty client or environment values are treated as unset, and an empty per-request string is replaced with the resolved client value. The SDK leaves non-string values unchanged, and applications should not use them for cache scoping.

Multi-user services must provide a stable, non-empty, opaque value for each user (or group whose members may share cache-hit timing) on every eligible request. Do not use a raw user identifier, API key, or encryption key. A single client, environment, or generated value groups all requests using it under the same API identity. If persistence is unavailable, the SDK uses an in-memory value and cache continuity ends when the process exits.

## Configuration Options

### TinfoilAI.create() Parameters

```swift
let client = try await TinfoilAI.create(
    apiKey: String? = nil,              // API key (uses TINFOIL_API_KEY env var if nil)
    baseURL: String? = nil,             // Proxy server URL (requests go directly to enclave if nil)
    enclaveURL: String? = nil,          // Custom enclave URL (auto-selects router if nil)
    githubRepo: String = "tinfoilsh/confidential-model-router", // GitHub repo for verification
    parsingOptions: ParsingOptions = .relaxed,  // OpenAI parsing options
    userCacheSecret: String? = nil,             // Prompt cache scoping secret (see "Prompt Cache Scoping")
    onVerification: VerificationCallback? = nil // Verification callback
)

// Returns: TinfoilAI - A client with the same API as OpenAI
```

### Proxy Server Support

See the [Proxy Server Guide](https://docs.tinfoil.sh/guides/proxy-server) for routing requests through a proxy while maintaining end-to-end encryption.

## API Documentation

This library is a secure wrapper around the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI) that can be used with Tinfoil. The `TinfoilAI.create()` method returns a `TinfoilAI` client that provides the same API as the OpenAI client, configured for secure communication with Tinfoil enclaves.

For complete documentation, see:
- [Swift SDK Documentation](https://docs.tinfoil.sh/sdk/swift-sdk)
- [MacPaw OpenAI SDK Documentation](https://github.com/MacPaw/OpenAI)

## Requirements

- iOS 17.0+ / macOS 12.0+
- Swift 5.9+
- Xcode 15.0+

## Reporting Vulnerabilities

Please report security vulnerabilities by emailing [security@tinfoil.sh](mailto:security@tinfoil.sh).

We aim to respond to (legitimate) security reports within 24 hours.
