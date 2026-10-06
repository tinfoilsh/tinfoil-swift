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

## Verification

Receive each verification result through an optional callback, invoked once during `create` and again whenever the client re-verifies because the attestation expired or the enclave rotated its key:

```swift
let client = try await TinfoilAI.create(
    apiKey: "YOUR_API_KEY",
    onVerification: { result in
        switch result {
        case .success(let verification):
            print("Enclave: \(verification.enclaveHost)")
            print("Code: \(verification.configRepo) \(verification.codeTag ?? verification.codeDigest)")
            print("Valid until: \(verification.freshnessExpiresAt)")
        case .failure(let error):
            print("Verification failed: \(error)")
        }
    }
)
```

A verification stops authorizing new requests at `freshnessExpiresAt`; the client verifies again before sending the next one. `verifiedAt` is when the document was appraised, by the device's clock; it is not an attested timestamp.

To verify an enclave without sending inference requests, use `SecureClient`:

```swift
let verifier = try SecureClient() // or SecureClient(enclave: "enclave.example.com", repo: "org/repo")
let verification = try await verifier.verify()
```

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
    enclave: String? = nil,                       // enclave host; one of Tinfoil's routers is discovered if nil
    repo: String = "tinfoilsh/confidential-model-router", // owner/name[@tag][@sha256:digest]
    attestationRelay: String? = nil,              // host that relays attestation requests to the enclave
    verificationPolicy: VerificationPolicy = VerificationPolicy(), // register pins, freshness bound
    parsingOptions: ParsingOptions = .relaxed,
    customHeaders: [String: String] = [:],
    tinfoilEvents: Set<TinfoilEvent> = [],
    userCacheSecret: String? = nil,
    onVerification: VerificationCallback? = nil
)
```

A custom `repo` needs an `enclave`, since only Tinfoil's routers are discovered.

To route through a proxy, set `baseURL` to it; request bodies stay encrypted to the enclave. Attestation is fetched from the enclave directly unless `attestationRelay` names a host, such as your proxy, that relays it over HTTPS. See the [proxy server guide](https://docs.tinfoil.sh/guides/proxy-server).

## API Documentation

This library is a drop-in replacement for the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI). All methods and types are identical; see its documentation for API usage.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
