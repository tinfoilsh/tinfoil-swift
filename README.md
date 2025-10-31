# Tinfoil Swift

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20|%20macOS-blue.svg)](https://developer.apple.com)
[![Tests](https://github.com/tinfoilsh/tinfoil-swift/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-swift/actions/workflows/test.yml)
[![Docs](https://img.shields.io/badge/Docs-Swift%20SDK-blue.svg)](https://docs.tinfoil.sh/sdk/swift-sdk)

A secure Swift SDK for communicating with AI models running in Tinfoil's confidential computing enclaves. This SDK wraps the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI) with additional security features including automatic enclave verification, certificate pinning, and attestation validation.

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
- **Certificate Pinning**: Prevents man-in-the-middle attacks
- **Streaming Support**: Real-time streaming responses
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

### Verification and Security

Tinfoil Swift performs two types of verification:
1. **Attestation verification**: Validates the enclave is running genuine Tinfoil code
2. **TLS certificate verification**: Ensures you're connecting to the verified enclave

#### Verification Callback

You can receive the verification document through an optional callback:

```swift
let verificationCallback: VerificationCallback = { verificationDocument in
    if let doc = verificationDocument {
        print("✅ Attestation verification successful")
        print("Code measurement: \(doc.codeMeasurement.registers.first ?? "")")
        print("Security verified: \(doc.securityVerified)")
    }
}

let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY",
    onVerification: verificationCallback
)
```


## Configuration Options

### TinfoilAI.create() Parameters

```swift
let client = try await TinfoilAI.create(
    apiKey: String? = nil,              // API key (uses TINFOIL_API_KEY env var if nil)
    enclaveURL: String? = nil,           // Custom enclave URL (auto-selects router if nil)
    githubRepo: String = "org/repo", // GitHub repo for verification (default: "tinfoilsh/confidential-model-router")
    parsingOptions: ParsingOptions = .relaxed,  // OpenAI parsing options
    onVerification: ((VerificationDocument?) -> Void)? = nil // Verification callback
)

// Returns: OpenAI - The configured OpenAI client
```

## API Documentation

This library is a secure wrapper around the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI) that can be used with Tinfoil. The `TinfoilAI.create()` method returns an OpenAI client configured for secure communication with Tinfoil enclaves.

For complete documentation, see:
- [Swift SDK Documentation](https://docs.tinfoil.sh/sdk/swift-sdk)
- [MacPaw OpenAI SDK Documentation](https://github.com/MacPaw/OpenAI)

## Requirements

- iOS 17.0+ / macOS 12.0+
- Swift 5.9+
- Xcode 15.0+

## Security

### Reporting Vulnerabilities

Please report security vulnerabilities to [security@tinfoil.sh](mailto:security@tinfoil.sh) or by opening an issue on GitHub.

## License

GNU Affero General Public License (AGPL) v3.0
