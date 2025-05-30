# Tinfoil Swift

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20|%20macOS-blue.svg)](https://developer.apple.com)

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/tinfoilsh/tinfoil-swift.git", branch: "main")
]
```

Note: Tinfoil Swift requires the MacPaw OpenAI SDK as a dependency. When you add Tinfoil Swift through Swift Package Manager, the OpenAI SDK will be automatically included as a dependency.

Or in Xcode:

1. Go to File > Add Packages...
2. Enter the repository URL: `https://github.com/tinfoilsh/tinfoil-swift.git`
3. Select the version you want to use
4. Click "Add Package"

Xcode will automatically resolve and include the OpenAI SDK dependency when you add the Tinfoil Swift package.

## Quick Start

The Tinfoil Swift client is a wrapper around the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI) and provides secure communication with Tinfoil enclaves. It has the same API as the OpenAI SDK, with additional security features:

- Automatic verification that the endpoint is running in a secure Tinfoil enclave
- TLS certificate pinning to prevent man-in-the-middle attacks
- Attestation validation to ensure enclave integrity

```swift
import TinfoilAI
import OpenAI

// Create a secure OpenAI client
let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY", // Optional, will use TINFOIL_API_KEY env var if not provided
    githubRepo: "tinfoilsh/model-repo",
    enclaveURL: "enclave.example.com"
)

// Use the client directly - it's a standard OpenAI client with security built-in
let chatQuery = ChatQuery(
    messages: [
        .user(.init(content: .string("Say this is a test")))
    ],
    model: "model-name"
)

let chatResponse = try await client.chats(query: chatQuery)
print(chatResponse.choices.first?.message.content ?? "No response")
```

### Usage

The `TinfoilAI.create()` method returns a standard OpenAI client that's been configured with:
- Secure enclave verification
- Certificate pinning
- Automatic TLS validation

Once created, you can use it exactly like the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI):

```swift
// Create the secure client
let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY", // Optional, will use TINFOIL_API_KEY env var if not provided
    githubRepo: "tinfoilsh/model-repo",
    enclaveURL: "enclave.example.com"
)

// Example: Create a chat completion
let query = ChatQuery(
    messages: [
        .system(.init(content: .string("You are a helpful assistant."))),
        .user(.init(content: .string("Hello, how are you?")))
    ],
    model: "model-name"
)
let response = try await client.chats(query: query)
```

## Advanced Features

### Streaming Chat Completions

Tinfoil Swift supports streaming chat completions, allowing you to receive responses as they are generated in real-time. This is particularly useful for longer responses or when you want to display content as it's being generated.

```swift
let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY",
    githubRepo: "tinfoilsh/model-repo", 
    enclaveURL: "enclave.example.com"
)

let chatQuery = ChatQuery(
    messages: [
        .user(.init(content: .string("Tell me a story about AI safety")))
    ],
    model: "model-name"
)

var accumulatedContent = ""

// Stream the response
for try await result in client.chatsStream(query: chatQuery) {
    if let choice = result.choices.first,
       let delta = choice.delta.content {
        accumulatedContent += delta
        print("Received: \(delta)")
    }
    
    // Check for completion
    if let finishReason = result.choices.first?.finishReason {
        print("Stream finished with reason: \(finishReason)")
        break
    }
}

print("Complete response: \(accumulatedContent)")
```

### Non-Blocking Verification

By default, Tinfoil Swift enforces strict security by failing requests when enclave verification or certificate pinning fails. With non-blocking verification, you can allow requests to proceed even if verification fails, while still being notified of the verification status through a callback. This prioritizes availability over security.

```swift
// Set up a callback to handle verification results
let verificationCallback: NonblockingVerification = { verificationPassed in
    if verificationPassed {
        print("✅ Enclave verification passed - connection is secure")
    } else {
        print("❌ Enclave verification failed - connection may not be secure")
        // Handle verification failure (log, alert user, etc.)
    }
}

// Create client with non-blocking verification
let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY",
    githubRepo: "tinfoilsh/model-repo",
    enclaveURL: "enclave.example.com",
    nonblockingVerification: verificationCallback
)

// Requests will proceed even if certificate verification fails
let chatQuery = ChatQuery(
    messages: [
        .user(.init(content: .string("Hello, I need a quick response!")))
    ],
    model: "model-name"
)

// This request will go through regardless of verification status
let response = try await client.chats(query: chatQuery)
print(response.choices.first?.message.content ?? "No response")

// The verification callback will notify you whether verification passed or failed
```

**Important Security Warning**: When using non-blocking verification, requests will proceed even if enclave verification or certificate pinning fails. This means your requests may be sent to an unverified endpoint. The verification callback will inform you of the failure, but the connection continues regardless. Only use this mode when availability is more important than security guarantees.

### Manual Verification and Certificate Pinning

For advanced use cases, you can perform manual verification and use certificate pinning directly:

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

### Certificate Pinning

**Note**: Certificate pinning is performed automatically when you use `TinfoilAI.create()`. The following example shows how to use certificate pinning manually for advanced use cases.

For additional control, you can use certificate pinning directly to ensure you're connecting to the exact expected enclave:

```swift
// First, get the expected fingerprint through verification
let secureClient = SecureClient(
    githubRepo: "tinfoilsh/model-repo",
    enclaveURL: "enclave.example.com"
)

let verificationResult = try await secureClient.verify()
let expectedFingerprint = verificationResult.publicKeyFP

// Create a client with certificate pinning
let tinfoilClient = try TinfoilClient.create(
    apiKey: "YOUR_API_KEY",
    enclaveURL: "enclave.example.com",
    expectedFingerprint: expectedFingerprint,
    parsingOptions: .relaxed
)

// Now all requests will use certificate pinning for maximum security
let chatQuery = ChatQuery(
    messages: [.user(.init(content: .string("Secure message")))],
    model: "model-name"
)

let response = try await tinfoilClient.underlyingClient.chats(query: chatQuery)

// Clean up when done
tinfoilClient.shutdown()
```

## API Documentation

This library is a secure wrapper around the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI) that can be used with Tinfoil. The `TinfoilAI.create()` method returns a standard OpenAI client with built-in security features. See the [MacPaw OpenAI SDK documentation](https://github.com/MacPaw/OpenAI) for complete API usage and documentation.

## Requirements

- iOS 17.0+ / macOS 12.0+
- Swift 5.9+
- Xcode 15.0+

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to security reports within 24 hours and will keep you updated on our progress.
