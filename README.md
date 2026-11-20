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
    .package(url: "https://github.com/tinfoilsh/tinfoil-swift.git", .upToNextMinor(from: "0.9.0-rc.6"))
],
targets: [
    .target(name: "YourApp", dependencies: [.product(name: "Tinfoil", package: "tinfoil-swift")])
]
```

Or in Xcode, File > Add Packages, enter `https://github.com/tinfoilsh/tinfoil-swift.git`, and choose a version. While the SDK is below 1.0, a minor version can break the API, so follow minor versions deliberately (`.upToNextMinor`).

## Quick Start

```swift
import Tinfoil

// Enclave verification and encryption happen automatically.
let client = try await OpenAIClient(apiKey: "YOUR_API_KEY")

let query = ChatQuery(
    messages: [.user(.init(content: .string("Hello, world!")))],
    model: "gpt-oss-120b" // see https://docs.tinfoil.sh/models/chat
)

let response = try await client.chats(query: query)
print(response.choices.first?.message.content ?? "No response")
```

`OpenAIClient(apiKey:)` uses one of Tinfoil's routers. The SDK is layered: an HTTP client carries the route, its verification and its transport, and an `OpenAIClient` is built over one of them. To choose the enclave, name what it must run, send through a proxy, relay attestation, tighten the verification policy or reject verifications, create an `EnclaveHTTPClient` and build the `OpenAIClient` over it:

```swift
let enclave = try await EnclaveHTTPClient(enclave: "enclave.example.com", trust: .repo("org/repo@v1.2.3"))
let client = try OpenAIClient(httpClient: enclave, apiKey: "YOUR_API_KEY")
```

The trust argument names who vouches for the config that the enclave runs: `.repo(_:)` a GitHub repository, `owner/name[@tag][@sha256:digest]`, whose signed release the enclave must prove; `.project(_:registryIDs:)` a config registry project, `org/project[@revision][@sha256:digest]`; `.signedBy(keys:project:)` configs that your keys sign; `.authorizedBy(_:)` configs that your closure approves; `.embeddedConfig(_:name:)` the exact config bytes that you supply; and `.either(repo:project:)` either of a repository and a project, for the migration to registry projects.

`RouterHTTPClient` does the same for Tinfoil's routers, and `GatewayHTTPClient` for the gateway. Each can also send requests of your own with `data(for:)`. The enclave and router clients are verified before they are returned, verify again by themselves when the verification expires or the enclave rejects its key, and can be closed with `close()`. Their doc comments describe the options and request rules.

### Transport

The enclave and router clients pin each TLS connection to the attested key by default (`transport: .tls`), which protects the whole request and response. With `transport: .ehbp(proxyURL:)`, request and response bodies are sealed to the attested key instead, so they stay private through the proxy; the method, URL and headers are not sealed, and neither is a request without a body or its response. `OpenAIClient` adds the API path, `/v1/` by default (`OpenAIOptions.apiPath`), under the proxy URL or, without one, the origin of the enclave or router that the HTTP client verified. The gateway client always uses EHBP, since the gateway sits between the client and the replica.

### Verification policy

A `Policy` sets what an enclave must prove on top of its trust. Every HTTP client takes one as the `policy` option of its options value, and an `OpenAIClient` uses its HTTP client's:

```swift
let policy = Policy(
    pinnedRegisters: Verification.Measurement(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: registers),
    freshnessMaxAge: 3600
)
let enclave = try await EnclaveHTTPClient(enclave: host, trust: trust, options: .init(policy: policy))
```

It also takes the runtime and platform artifacts' trust (`artifacts: .endorsed(freshnessKeys:)` or `.embedded(runtime:platform:freshnessKeys:)`). Pass the `verificationCheck` option to inspect each `Verification` before its keys are used, and throw to reject it.

### Gateway (experimental)

`GatewayHTTPClient` sends each request through Tinfoil's inference gateway, sealed with EHBP to a verified replica of the model that the request names. Models can be pinned to repositories with the `modelPins` option. The gateway API may change in a later release.

## Documentation

- [Swift SDK documentation](https://docs.tinfoil.sh/sdk/swift-sdk) and the [proxy server guide](https://docs.tinfoil.sh/guides/proxy-server).
- Multi-user services must scope prompt caches to each end user, with a per-request `user_cache_secret` in `extraBody`, or with the `userCacheSecret` option of a `RouterHTTPClient` or `GatewayHTTPClient`. The router reads the secret; the gateway client derives a cache salt from it on the device and sends the salt, not the secret, in a JSON request body. Without one, the router and gateway clients use a random secret that is generated once per process and that its clients share; the SDK reads no environment variable or file for it. An `EnclaveHTTPClient` sends bodies as they are, so set the field per request when it points at a router. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).
- `audioCreateSpeechStream(query:options:)` delivers decrypted audio in chunks that can split PCM samples or frames. The stream buffers without bound, so consume it promptly.
- All OpenAI methods and types are unchanged; see the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI).

## Development

Run `swift test`. Live tests run only with `RUN_TINFOIL_INTEGRATION=true`, and those that send inference requests also need `TINFOIL_API_KEY`. `./update_verifier.sh [tag]` pins a new tinfoil-go release of the verifier framework.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
