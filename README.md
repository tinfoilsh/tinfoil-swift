# Tinfoil Swift Client

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20|%20macOS-blue.svg)](https://developer.apple.com)
[![Tests](https://github.com/tinfoilsh/tinfoil-swift/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-swift/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/swift-sdk)

A Swift client for verifiably private AI inference with Tinfoil. It wraps the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI) with the same API, and before sending any request it verifies the enclave's attestation and encrypts the request body to the attested key using [EHBP](https://docs.tinfoil.sh/resources/ehbp), so only the verified enclave can read it.

For complete documentation, see the [Swift SDK documentation](https://docs.tinfoil.sh/sdk/swift-sdk).

## Installation

Requires iOS 17 or macOS 14, and Swift 5.9.

```swift
dependencies: [
    .package(url: "https://github.com/tinfoilsh/tinfoil-swift.git", branch: "main")
]
```

Or in Xcode, File > Add Packages and enter `https://github.com/tinfoilsh/tinfoil-swift.git`.

## Quick Start

```swift
import TinfoilAI

// Reads TINFOIL_API_KEY from the environment when apiKey is omitted.
// Enclave verification and encryption happen automatically.
let client = try await TinfoilAI.create(apiKey: "YOUR_API_KEY")

let query = ChatQuery(
    messages: [.user(.init(content: .string("Hello, world!")))],
    model: "llama3-3-70b" // see https://docs.tinfoil.sh/models/catalog
)

let response = try await client.chats(query: query)
print(response.choices.first?.message.content ?? "No response")
```

### Streaming

```swift
for try await chunk in client.chatsStream(query: query) {
    if let delta = chunk.choices.first?.delta.content {
        print(delta, terminator: "")
    }
}
```

### Streaming speech

```swift
let speech = AudioSpeechQuery(
    model: "qwen3-tts",
    input: "Hello, world!",
    voice: .custom("aiden"),
    responseFormat: .pcm,
    streamFormat: .audio
)
let stream = client.audioCreateSpeechStream(
    query: speech,
    options: .init(expectedContentType: "audio/pcm")
)
```

Iterate over `stream` to receive decrypted audio in `AudioSpeechResult.audio`. Chunks can split PCM samples or frames, and the stream buffers without bound, so consume promptly. Cancel the consuming task to stop the request.

## Verification document

Receive the verification result through an optional callback, invoked once during `create` and again whenever the enclave rotates its key:

```swift
let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY",
    onVerification: { document in
        guard let doc = document else { return }
        print("Code fingerprint: \(doc.codeFingerprint)")
        print("Enclave fingerprint: \(doc.enclaveFingerprint)")
        print("Release: \(doc.releaseTag ?? "unavailable")")
        print("Verifier: \(doc.verifier.name) \(doc.verifier.version)")
        print("Verified at: \(doc.verifiedAt ?? "unknown")")
        print("Security verified: \(doc.securityVerified)")
    }
)
```

`verifiedAt` is recorded from the local clock after successful verification. It is not an attested timestamp or a freshness guarantee.

## Prompt Cache Scoping

The router partitions prompt caches by API identity and a `user_cache_secret` that the SDK adds to eligible requests. By default it generates one and persists it at `~/.tinfoil/user_cache_secret`, which is suitable for single-user applications. Multi-user services should scope each request to its end user:

```swift
// Pin a stable, opaque secret for this client (or set TINFOIL_USER_CACHE_SECRET).
let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY",
    userCacheSecret: secret
)

// A per-request value wins over the client-level secret.
let query = ChatQuery(
    messages: [.user(.init(content: .string("Hello!")))],
    model: "llama3-3-70b",
    extraBody: ["user_cache_secret": .string(perUserSecret)]
)
```

See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching) for resolution order and guidance on choosing a scope.

## Advanced Functionality

`TinfoilAI.create()` accepts:

```swift
TinfoilAI.create(
    apiKey: String? = nil,                        // falls back to TINFOIL_API_KEY
    apiKeyProvider: (() -> String?)? = nil,       // resolve the key per request instead
    baseURL: String? = nil,                       // proxy URL; requests go directly to the enclave if nil
    githubRepo: String = "tinfoilsh/confidential-model-router",
    attestationBundleURL: String? = nil,          // fetch the attestation bundle through the proxy
    parsingOptions: ParsingOptions = .relaxed,
    customHeaders: [String: String] = [:],
    tinfoilEvents: Set<TinfoilEvent> = [],
    userCacheSecret: String? = nil,
    onVerification: VerificationCallback? = nil
)
```

To route through a proxy, set both `baseURL` and `attestationBundleURL` to the proxy; request bodies stay encrypted to the enclave. See the [proxy server guide](https://docs.tinfoil.sh/guides/proxy-server).

## API Documentation

This library is a drop-in replacement for the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI). All methods and types are identical; see its documentation for API usage.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
