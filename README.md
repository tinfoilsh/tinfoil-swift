# Tinfoil Swift

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20|%20macOS-blue.svg)](https://developer.apple.com)

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/tinfoilsh/tinfoil-swift.git", from: "0.0.1"),
]
```

Note: Tinfoil Swift requires OpenAI-Kit as a dependency. When you add Tinfoil Swift through Swift Package Manager, OpenAI-Kit will be automatically included as a dependency.

Or in Xcode:

1. Go to File > Add Packages...
2. Enter the repository URL: `https://github.com/tinfoilsh/tinfoil-swift.git`
3. Select the version you want to use
4. Click "Add Package"

Xcode will automatically resolve and include the OpenAI-Kit dependency when you add the Tinfoil Swift package.

## Quick Start

The Tinfoil Swift client is a wrapper around the [OpenAI-Kit](https://github.com/dylanshine/openai-kit) and provides secure communication with Tinfoil enclaves. It has the same API as the OpenAI-Kit client, with additional security features:

- Automatic verification that the endpoint is running in a secure Tinfoil enclave
- TLS certificate pinning to prevent man-in-the-middle attacks
- Attestation validation to ensure enclave integrity

```swift
import TinfoilKit
import OpenAIKit

// Create a secure client for a specific enclave and model repository
let tinfoil = try await TinfoilAI(
    apiKey: "api-key", // Optional, will use TINFOIL_API_KEY env var if not provided
    githubRepo: "tinfoilsh/model-repo",
    enclaveURL: "enclave.example.com"
)

// Access the OpenAIKit client through the client property
// Note: enclave verification happens automatically during initialization
let chatResponse = try await tinfoil.client.chats.create(
    model: "llama3.2:1b",
    messages: [
        Chat.Message(role: .user, content: "Say this is a test")
    ]
)

print(chatResponse.choices.first?.message.content ?? "No response")

// Resources are automatically cleaned up when tinfoilClient is deallocated
```

### Usage

```swift
// 1. Create a TinfoilAI client
let tinfoil= try await TinfoilAI(
    apiKey: "api-key", // Optional, will use TINFOIL_API_KEY env var if not provided
    githubRepo: "tinfoilsh/model-repo",
    enclaveURL: "enclave.example.com"
)

// 2. Use the underlying OpenAI-Kit client
// See https://github.com/dylanshine/openai-kit for API documentation
let openAIClient = tinfoil.client

// Example: Create a chat completion
let response = try await openAIClient.chats.create(
    model: "gpt-4",
    messages: [
        Chat.Message(role: .system, content: "You are a helpful assistant."),
        Chat.Message(role: .user, content: "Hello, how are you?")
    ]
)
```

### Advanced functionality

```swift
// Manual verification with progress callbacks
let verificationCallbacks = VerificationCallbacks(
    onCodeVerificationComplete: { result in
        switch result.status {
        case .success(let digest):
            print("Code verification successful: \(digest)")
        case .failure(let error):
            print("Code verification failed: \(error)")
        default:
            break
        }
    },
    onRuntimeVerificationComplete: { result in
        switch result.status {
        case .success(let digest):
            print("Runtime verification successful: \(digest)")
        case .failure(let error):
            print("Runtime verification failed: \(error)")
        default:
            break
        }
    },
    onSecurityCheckComplete: { result in
        switch result.status {
        case .success:
            print("Security check passed: Code and runtime match")
        case .failure(let error):
            print("Security check failed: \(error)")
        default:
            break
        }
    }
)

let secureClient = SecureClient(
    githubRepo: "tinfoilsh/model-repo",
    enclaveURL: "enclave.example.com",
    callbacks: verificationCallbacks
)

let verificationResult = try await secureClient.verify()
if verificationResult.isMatch {
    print("Verification successful!")
    print("Code digest: \(verificationResult.codeDigest)")
    print("Runtime digest: \(verificationResult.runtimeDigest)")
    print("Key fingerprint: \(verificationResult.publicKeyFP)")
} else {
    print("Verification failed: Code and runtime digests do not match")
}
```

## API Documentation

This library is a secure wrapper around [OpenAI-Kit](https://github.com/dylanshine/openai-kit) that can be used with Tinfoil. Once you have created a `TinfoilAI` instance, you can access the underlying OpenAIKit client through the `client` property. See the [OpenAI-Kit documentation](https://github.com/dylanshine/openai-kit) for complete API usage and documentation.

## Requirements

- iOS 17.0+ / macOS 12.0+
- Swift 5.9+
- Xcode 15.0+

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to security reports within 24 hours and will keep you updated on our progress.
