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

### Relays: reaching only your own origin

A client normally fetches each enclave's attestation document from the enclave, and the router client fetches its list of routers from `https://atc.tinfoil.sh/routers`. To reach only your own origin, for example to keep the user's IP address from enclaves or behind a network policy that allows one host, send requests through an EHBP proxy and fetch both through relays on the same origin:

```swift
let origin = URL(string: "https://app.example/tinfoil")!
let router = try await RouterHTTPClient(options: .init(
    transport: .ehbp(proxyURL: origin.appendingPathComponent("proxy")),
    fetchAttestation: .relay(origin),
    fetchRouterList: .relay(origin)
))
```

The attestation relay serves `GET {url}/.well-known/tinfoil-attestation?nonce={hex}&enclave={host}` by forwarding it to `https://{host}/.well-known/tinfoil-attestation?nonce={hex}` and returning the body unchanged; it should forward only to enclave hosts that you expect. The router-list relay serves `GET {url}/routers` from `https://atc.tinfoil.sh/routers`. Neither is trusted: every document is verified as a directly fetched one is, and the list only proposes routers, which discovery still verifies in a random order. With EHBP, though, a router host that the list names receives the request headers, so the list's source is trusted not to name an impostor. `AttestationFetcher { host, nonce in … }` and `RouterListFetcher { … }` take closures of your own instead.

### Verification policy

A `Policy` sets what an enclave must prove on top of its trust. Every HTTP client takes one as the `policy` option of its options value, and an `OpenAIClient` uses its HTTP client's:

```swift
let policy = Policy(
    pinnedRegisters: VerifiedFacts.Measurement(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: registers),
    freshnessMaxAge: 3600
)
let enclave = try await EnclaveHTTPClient(enclave: host, trust: trust, options: .init(policy: policy))
```

It also takes the runtime and platform artifacts' trust (`artifacts: .endorsed(freshnessKeys:)` or `.embedded(runtime:platform:freshnessKeys:)`). Pass the `verificationCheck` option to inspect the `VerifiedFacts` of each verification before its keys are used, and throw to reject it.

### Verification reports

Every verification returns a `VerificationReport`: one step for each layer of the verifier (`envelope`, `provenance`, `quote` and `policy`), each `passed`, `failed`, `skipped` or `notRun`, and the `verifiedFacts` that the document proved. When the verifier rejects a document, the client throws `TinfoilError.attestationError`, whose `verificationError` carries the report, with the step that failed and the `partialFacts` that the steps before it established, such as the expected and measured registers side by side. Its key fingerprints are only the document's claim. A report authorizes nothing; the client binds its channel only to verified facts.

```swift
let client = try await EnclaveHTTPClient(enclave: host, trust: trust, options: .init(
    onVerification: { host, result in
        // Called once for every attempt, outside the client's actors.
        if case .failure(.attestationError(let failure)) = result, let rejected = failure.verificationError {
            print(host, rejected.report.steps.map { "\($0.layer): \($0.status)" })
        }
    }
))
let report = try await client.ensureVerified()
let last = await client.lastVerification  // the most recent attempt, success or failure
```

`JSONEncoder` writes a report, its `verifiedFacts` or its `partialFacts` and their parts (but not a `CPUEvidence` alone, whose measurement `MeasuredFacts` writes as `cpu_measurement`), in the JSON form that every Tinfoil SDK writes, so that a verification user interface or a service that relays results reads the reports of every SDK in the same way:

```swift
let json = try JSONEncoder().encode(report)
// {"schema_version":1,"steps":[{"layer":"envelope","status":"passed"},...],
//  "verified_facts":{"config_repo":"...","code_digest":"...","enclave_measurement":{"platform":"tdx","mrtd":"...",...},
//  "crypto_material":[...],"freshness_expires_at":"2026-12-01T16:00:00Z"},"metadata":{...}}
```

Member names are snake_case, hex is lowercase and times are RFC 3339 in UTC. A fact that was not established is omitted, measurements name their registers by platform, and the TLS and HPKE keys appear only in `verified_facts.crypto_material`. The JSON is for display and transport, and it authorizes nothing: the types are `Encodable` but not `Decodable`, so no report or verified facts can be read back from JSON, and a channel is never bound to a key that was read from it.

### Gateway (experimental)

`GatewayHTTPClient` sends each request through Tinfoil's inference gateway, sealed with EHBP to a verified replica of the model that the request names. It serves only the models that are pinned to repositories with the `modelPins` option, so at least one pin is required, and a request for any other model fails with a configuration error without contacting a replica. The gateway API may change in a later release.

## Documentation

- [Swift SDK documentation](https://docs.tinfoil.sh/sdk/swift-sdk) and the [proxy server guide](https://docs.tinfoil.sh/guides/proxy-server).
- Multi-user services must scope prompt caches to each end user, with a per-request `user_cache_secret` in `extraBody`, or with the `userCacheSecret` option of a `RouterHTTPClient` or `GatewayHTTPClient`. The router reads the secret; the gateway client derives a cache salt from it on the device and sends the salt, not the secret, in a JSON request body. Without one, the router and gateway clients use a random secret that is generated once per process and that its clients share; the SDK reads no environment variable or file for it. An `EnclaveHTTPClient` sends bodies as they are, so set the field per request when it points at a router. See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).
- `audioCreateSpeechStream(query:options:)` delivers decrypted audio in chunks that can split PCM samples or frames. The stream buffers without bound, so consume it promptly.
- All OpenAI methods and types are unchanged; see the [MacPaw OpenAI SDK](https://github.com/MacPaw/OpenAI).

## Development

Run `swift test`. Live tests run only with `RUN_TINFOIL_INTEGRATION=true`, and those that send inference requests also need `TINFOIL_API_KEY`. `./update_verifier.sh [tag]` pins a new tinfoil-go release of the verifier framework.

To test against a TinfoilGo framework that you built from tinfoil-go's source with `scripts/build-mobile.sh`, set `TINFOIL_GO_XCFRAMEWORK` to its path, relative to this package. With a framework that was built with `MOBILE_BUILD_TAGS=tinfoil_conformance`, also set `TINFOIL_CONFORMANCE=1` and `TINFOIL_CONFORMANCE_VECTORS` to the vectors directory of [tinfoil-conformance](https://github.com/tinfoilsh/tinfoil-conformance) to verify the vectors of the report's JSON golden cases through it:

```sh
TINFOIL_GO_XCFRAMEWORK=.build/TinfoilGo.xcframework TINFOIL_CONFORMANCE=1 \
TINFOIL_CONFORMANCE_VECTORS=/path/to/tinfoil-conformance/vectors swift test
```

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
