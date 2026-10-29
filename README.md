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
],
targets: [
    .target(name: "YourApp", dependencies: [.product(name: "Tinfoil", package: "tinfoil-swift")])
]
```

Or in Xcode, File > Add Packages and enter `https://github.com/tinfoilsh/tinfoil-swift.git`.

## Quick Start

```swift
import Tinfoil

// Reads TINFOIL_API_KEY from the environment when apiKey is omitted.
// Enclave verification and encryption happen automatically.
let client = try await Client(apiKey: "YOUR_API_KEY")

let query = ChatQuery(
    messages: [.user(.init(content: .string("Hello, world!")))],
    model: "gpt-oss-120b" // see https://docs.tinfoil.sh/models/chat
)

let response = try await client.chats(query: query)
print(response.choices.first?.message.content ?? "No response")
```

To choose the enclave, pin the repo to a tag or digest, send through a proxy, relay attestation, tighten the verification policy, or reject verifications, use an `EnclaveOpenAIClient`, which has the same OpenAI methods:

```swift
let client = try await EnclaveOpenAIClient(enclave: "enclave.example.com", repo: "org/repo@v1.2.3", apiKey: "YOUR_API_KEY")
```

`RouterOpenAIClient` does the same for one of Tinfoil's routers, which `Client` uses today. Each sends through an `EnclaveHTTPClient` or `RouterHTTPClient`, which you can also create directly. Both are verified before they're returned, and send requests of their own with `data(from:)` and `data(for:)`, over TLS pinned to the attested key (the default for an enclave you name) or sealed with EHBP. Their doc comments describe the callbacks, refresh, and request rules.

## Documentation

- [Swift SDK documentation](https://docs.tinfoil.sh/sdk/swift-sdk) and the [proxy server guide](https://docs.tinfoil.sh/guides/proxy-server).
- Multi-user services must scope prompt caches to each end user, with a per-request `user_cache_secret` in `extraBody`, or by passing `userCacheSecret` when creating a client for one of Tinfoil's routers, such as `RouterOpenAIClient`. Only the router reads it. `Client` reads its secret from `TINFOIL_USER_CACHE_SECRET` or `~/.tinfoil/user_cache_secret`. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).
- `audioCreateSpeechStream(query:options:)` delivers decrypted audio in chunks that can split PCM samples or frames. The stream buffers without bound, so consume it promptly.
- All OpenAI methods and types are unchanged; see the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI).

## Development

Run `swift test`. Live tests run only with `RUN_TINFOIL_INTEGRATION=true`, and those that send inference requests also need `TINFOIL_API_KEY`. `./update_verifier.sh [tag]` pins a new tinfoil-go release of the verifier framework.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
