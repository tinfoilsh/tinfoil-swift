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

An `EnclaveHandle` decides which enclave to verify and how. Without one, `create` uses a default handle that discovers one of Tinfoil's routers. Pass your own to choose the enclave, pin the repo to a tag or digest, relay attestation, tighten the policy, or observe and reject verifications:

```swift
let handle = try EnclaveHandle(
    enclave: "enclave.example.com",
    repo: "org/repo@v1.2.3",
    onEnclaveVerified: { verification in
        guard verification.codeMeasurement != nil else {
            throw MyPolicyError.unexpectedEnclave
        }
    },
    onVerificationResult: { result in
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
let client = try await TinfoilAI.create(apiKey: "YOUR_API_KEY", handle: handle)
```

The client verifies through the handle once during `create`, and again whenever the attestation expires or the enclave rotates its key. Each of these runs fetches the enclave's attestation document and verifies it, retrying a failed attempt once; a handle without an `enclave` may try several routers on its first run. The two callbacks see different things:

- `onEnclaveVerified` is called each time an enclave's evidence verifies, before the enclave is used. Throw to reject it: discovery moves to the next router; otherwise the run fails with `TinfoilError.enclaveRejected` and the enclave's key is never used. It runs synchronously, so a rejection cannot race a request.
- `onVerificationResult` is called once with each run's final result, success or failure, after any retries and rejections. It only observes.

A verification stops authorizing new requests at `freshnessExpiresAt`; the client verifies again before sending the next one. `verifiedAt` is when the document was appraised, by the device's clock; it is not an attested timestamp. A custom `repo` needs an `enclave`, since only Tinfoil's routers are discovered.

The same handle verifies without sending inference requests, and holds the latest result:

```swift
let verification = try await handle.verify()
```

### Other enclave endpoints

For endpoints outside the OpenAI API, the handle loads requests over TLS pinned to the enclave's attested key, with URLSession-like `data(from:)` and `data(for:)` methods that return `(Data, HTTPURLResponse)`. A URL without a host resolves against the verified enclave:

```swift
let (data, response) = try await handle.data(from: URL(string: "/health")!)

var request = URLRequest(url: URL(string: "/v1/status")!)
request.setValue("Bearer YOUR_API_KEY", forHTTPHeaderField: "Authorization")
let (body, status) = try await handle.data(for: request)
```

Requests go only to the verified enclave: an absolute URL for another host is refused, as is a redirect to another host or to plain HTTP, so credentials in headers never leave it. Each connection must present a certificate that passes the system's usual validation and whose key matches the attestation. Requests use the current verification and re-verify once it expires. If the enclave presents a key the attestation does not endorse before the request is sent, the handle verifies again and retries once; otherwise, or if it happens again, it throws `TinfoilError.attestationError`. Network failures, including a certificate the system does not trust, surface as `URLError`.

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
    handle: EnclaveHandle? = nil,                 // how the enclave is verified; a router is discovered if nil
    parsingOptions: ParsingOptions = .relaxed,
    customHeaders: [String: String] = [:],
    tinfoilEvents: Set<TinfoilEvent> = [],
    userCacheSecret: String? = nil
)
```

`EnclaveHandle(enclave:repo:attestationRelay:policy:onEnclaveVerified:onVerificationResult:)` takes the enclave host, the `owner/name[@tag][@sha256:digest]` repo, an attestation relay, a `VerificationPolicy` (register pins, freshness bound) and the two callbacks described under [Verification](#verification).

To route through a proxy, set `baseURL` to it; request bodies stay encrypted to the enclave. Attestation is fetched from the enclave directly unless the handle's `attestationRelay` names a host, such as your proxy, that relays it over HTTPS. See the [proxy server guide](https://docs.tinfoil.sh/guides/proxy-server).

## API Documentation

This library is a drop-in replacement for the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI). All methods and types are identical; see its documentation for API usage.

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
