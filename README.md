# Tinfoil Swift Client

[![Swift](https://img.shields.io/badge/Swift-5.9-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20|%20macOS-blue.svg)](https://developer.apple.com)
[![Tests](https://github.com/tinfoilsh/tinfoil-swift/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-swift/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/swift-sdk)

A Swift client for verifiably private AI inference with Tinfoil. It wraps the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI) with the same API. Before sending any request, it verifies the enclave's attestation with Tinfoil's attestation v3 verifier, bundled as the TinfoilGo framework, and then ties every request to the attested keys: each TLS connection is pinned to the attested certificate key, or each request body is sealed to the attested key with [EHBP](https://docs.tinfoil.sh/resources/ehbp). Only the verified enclave can read it.

Upgrading from 0.8.x or a 0.9.0 release candidate? See [MIGRATION.md](MIGRATION.md).

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

// Enclave verification and encryption happen automatically.
let client = try await Client(apiKey: "YOUR_API_KEY")

let query = ChatQuery(
    messages: [.user(.init(content: .string("Hello, world!")))],
    model: "gpt-oss-120b" // see https://docs.tinfoil.sh/models/chat
)

let response = try await client.chats(query: query)
print(response.choices.first?.message.content ?? "No response")
```

`Client` uses one of Tinfoil's routers. To choose the enclave, pin the repo to a tag or digest, send through a proxy, relay attestation, tighten the trust policy or reject verifications, use an `EnclaveOpenAIClient`, which has the same OpenAI methods:

```swift
let client = try await EnclaveOpenAIClient(
    enclave: "enclave.example.com",
    repo: "org/repo@v1.2.3",
    apiKey: "YOUR_API_KEY"
)
```

`RouterOpenAIClient` does the same for Tinfoil's routers. Each sends through an `EnclaveHTTPClient` or `RouterHTTPClient`, which you can also create directly to send requests of your own with `data(for:)`. Both are verified before they are returned, verify again by themselves when the verification expires or the enclave rejects its key, and can be closed with `close()`. Their doc comments describe the parameters and request rules.

### Transport

Every client pins each TLS connection to the attested key by default (`transportMode: .tls`), which protects the whole request and response. With `transportMode: .ehbp`, request and response bodies are sealed to the attested key instead, so they stay private through a proxy that you pass as `baseURL`; the method, URL and headers are not sealed.

### Trust policy

A `Verifier` sets what an enclave must prove, and every client takes one as `verifier`:

```swift
let verifier = try Verifier(
    pinnedRegisters: Verification.Measurement(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: registers),
    freshnessMaxAge: 3600
)
let client = try await EnclaveOpenAIClient(enclave: host, repo: repo, verifier: verifier, apiKey: key)
```

It also takes config registry IDs, config and freshness signing keys, embedded references, and a `configAuthorizer` closure for configs that your application approves. Pass `verificationCheck` to inspect each `Verification` before its keys are used, and throw to reject it.

### Gateway (experimental)

`GatewayOpenAIClient` sends each request through Tinfoil's inference gateway, sealed with EHBP to a verified replica of the model that the request names. Models can be pinned to repositories with `modelPins`. The gateway API may change in a later release.

## Documentation

- [Swift SDK documentation](https://docs.tinfoil.sh/sdk/swift-sdk) and the [proxy server guide](https://docs.tinfoil.sh/guides/proxy-server).
- Multi-user services must scope prompt caches to each end user, with a per-request `user_cache_secret` in `extraBody`, or by passing `userCacheSecret` when creating a router or gateway client, such as `RouterOpenAIClient` or `GatewayOpenAIClient`. The router reads the secret; the gateway clients derive a cache salt from it on the device and send the salt, not the secret, in a JSON request body. Without one, the router and gateway clients, and `Client`, use a random secret generated once per process and shared by its clients; the SDK reads no environment variable or file for it. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).
- `audioCreateSpeechStream(query:options:)` delivers decrypted audio in chunks that can split PCM samples or frames. The stream buffers without bound, so consume it promptly.
- All OpenAI methods and types are unchanged; see the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI).

## Development

Run `swift test`. Live tests run only with `RUN_TINFOIL_INTEGRATION=true`, and those that send inference requests also need `TINFOIL_API_KEY`. `./update_verifier.sh [tag]` pins a new tinfoil-go release of the verifier framework.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
