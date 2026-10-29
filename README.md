# Tinfoil Swift Client

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20|%20macOS-blue.svg)](https://developer.apple.com)
[![Tests](https://github.com/tinfoilsh/tinfoil-swift/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-swift/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/swift-sdk)

A Swift client for verifiably private AI inference with Tinfoil. It wraps the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI) with the same API, and before sending any request it verifies the enclave's attestation and encrypts the request body to the attested key using [EHBP](https://docs.tinfoil.sh/resources/ehbp), so only the verified enclave can read it.

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
import Tinfoil

// Reads TINFOIL_API_KEY from the environment when apiKey is omitted.
// Enclave verification and encryption happen automatically.
let client = try await TinfoilAI.create(apiKey: "YOUR_API_KEY")

let query = ChatQuery(
    messages: [.user(.init(content: .string("Hello, world!")))],
    model: "gpt-oss-120b" // see https://docs.tinfoil.sh/models/chat
)

let response = try await client.chats(query: query)
print(response.choices.first?.message.content ?? "No response")
```

To choose the enclave, pin the repo to a tag or digest, send through a proxy, relay attestation, tighten the verification policy, or reject verifications, pass an `EnclaveHTTPClient`:

```swift
let enclave = try EnclaveHTTPClient(enclave: "enclave.example.com", repo: "org/repo@v1.2.3", transportMode: .ehbp)
let client = try await TinfoilAI.create(apiKey: "YOUR_API_KEY", client: enclave)
```

`EnclaveHTTPClient.discoverRouter()` picks one of Tinfoil's routers instead, as `TinfoilAI.create` does by default. An `EnclaveHTTPClient` also sends requests of its own to the enclave with `data(from:)` and `data(for:)`, over TLS pinned to the attested key (the default for an enclave you name) or sealed with EHBP. Its doc comments describe the callbacks, refresh, and request rules.

## Documentation

- [Swift SDK documentation](https://docs.tinfoil.sh/sdk/swift-sdk) and the [proxy server guide](https://docs.tinfoil.sh/guides/proxy-server).
- Multi-user services must scope prompt caches to each end user by passing `userCacheSecret` when creating an `EnclaveHTTPClient`, or with a per-request `user_cache_secret` in `extraBody`; see [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).
- `audioCreateSpeechStream(query:options:)` delivers decrypted audio in chunks that can split PCM samples or frames. The stream buffers without bound, so consume it promptly.
- All OpenAI methods and types are unchanged; see the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI).

## Development

Run `swift test`. Live tests run only with `RUN_TINFOIL_INTEGRATION=true`, and those that send inference requests also need `TINFOIL_API_KEY`. `./update_verifier.sh [tag]` pins a new tinfoil-go release of the verifier framework.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
