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

The enclave and router clients pin each TLS connection to the attested key by default (`transport: .tls`), which protects the whole request and response. With `transport: .ehbp(proxyURL:)`, request and response bodies are sealed to the attested key instead, so they stay private through the proxy; the method, URL and headers are not sealed, and neither is a request without a body or its response. `OpenAIClient` adds the API path, `/v1/` by default, under the proxy URL or, without one, the origin of the enclave or router that the HTTP client verified; for a gateway client, under its URL. The gateway client always uses EHBP, since the gateway sits between the client and the replica. Set the API path, if the API is not at `/v1/`, with `OpenAIClient`'s `apiPath` argument, as in `try OpenAIClient(httpClient: enclave, apiPath: "/openai/v1/", apiKey: key)`; a proxy URL's path names where the proxy is mounted, never the API path.

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

Every verification returns a `VerificationReport`: one step for each layer of the verifier (`envelope`, `provenance`, `quote` and `policy`), each `passed`, `failed`, `skipped` or `notRun`, and the `verifiedFacts` that the document proved. When the verifier rejects a document, the client throws `TinfoilError.attestationError`, whose `verificationError` names the `layer` that rejected it and carries the report, with the step that failed and the `partialFacts` that the steps before it established, such as the expected and measured registers side by side. Its key fingerprints are only the document's claim. A report authorizes nothing; the client binds its channel only to verified facts. A rejection that the verifier reports without a report has no `verificationError`; its message leads with the layer, as in `quote: <detail>`.

```swift
let client = try await EnclaveHTTPClient(enclave: host, trust: trust, options: .init(
    onVerificationAttempt: { host, result in
        // Called once for every attempt, outside the client's actors.
        if case .failure(.attestationError(let failure)) = result, let rejected = failure.verificationError {
            print(host, rejected.report.steps.map { "\($0.layer): \($0.status)" })
        }
    }
))
let report = try await client.ensureVerified()
let current = await client.currentVerification  // the verification that requests use now, or nil
let last = await client.lastVerificationAttempt  // the most recent attempt, success or failure
```

The clients split the verification in use from the attempts that produced it:

| Call | I/O | Returns |
|---|---|---|
| `ensureVerified()` | Only if needed | The report of a verification that is valid now, verifying first if the cached one has expired or been discarded |
| `reverify()` | Always | The report of a new verification, or its error |
| `currentVerification` | None | The report of the verification that requests are bound to now: fresh and not discarded. Nil before the first success, after a `TinfoilError.attestationError` or the enclave's rejection of the verified key discarded it, and once it has expired |
| `lastVerificationAttempt` | None | The most recent attempt: its report if it passed, its error if it failed |
| `onVerificationAttempt` option | Push | Each attempt as it is decided, failed attempts included |

The two getters differ after a `reverify()` that fails for a reason other than attestation, such as a `TinfoilError.networkError`: `lastVerificationAttempt` returns the error, while `currentVerification` still returns the cached report, under which requests still go through until it expires. A `reverify()` that fails with `TinfoilError.attestationError` discards the cached verification, so `currentVerification` is nil and the next request verifies again. So does a request whose verified key the enclave rejects: the client discards the verification before it verifies again, so `currentVerification` is nil until that verification succeeds, even if it fails with a `TinfoilError.networkError`.

- Health and readiness checks call `ensureVerified()`. It returns at once while the cached verification is valid, and verifies when it isn't. Clients don't verify again in the background, so `currentVerification` is nil between the expiry of a verification and the next request; don't treat that as a failure.
- Status displays show `currentVerification` for the verification in use, and `lastVerificationAttempt` for the outcome of the latest attempt, which may be a failure.
- Live status and logging use `onVerificationAttempt`, which sees every attempt, including retries that `lastVerificationAttempt` has already moved past.

`JSONEncoder` writes a report, its `verifiedFacts` or its `partialFacts` and their parts (but not a `CPUEvidence` alone, whose measurement `MeasuredFacts` writes as `cpu_measurement`), in the JSON form that every Tinfoil SDK writes, so that a verification user interface or a service that relays results reads the reports of every SDK in the same way:

```swift
let json = try JSONEncoder().encode(report)
// {"schema_version":1,"steps":[{"layer":"envelope","status":"passed"},...],
//  "verified_facts":{"config_repo":"...","code_digest":"...","enclave_measurement":{"platform":"tdx","mrtd":"...",...},
//  "crypto_material":[...],"freshness_expires_at":"2026-12-01T16:00:00Z"},
//  "metadata":{"verified_at":"...","verifier":{...},"host":"enclave.example.com"}}
```

A report from one of the SDK's clients names the host that the client contacted in `metadata.host` (the enclave, even through a proxy; the chosen router, or each router that discovery tries; or the gateway replica), on every path that hands out a report, including a rejection's, so a proxy that passes a report on needn't add the host itself. The host is what the client connected to, not an attested fact, so it proves nothing about the enclave.

Member names are snake_case, hex is lowercase and times are RFC 3339 in UTC. A fact that was not established is omitted, measurements name their registers by platform, and the TLS and HPKE keys appear only in `verified_facts.crypto_material`. The JSON is for display and transport, and it authorizes nothing: the types are `Encodable` but not `Decodable`, so no report or verified facts can be read back from JSON, and a channel is never bound to a key that was read from it.

### Gateway (experimental)

`GatewayHTTPClient` sends each request through Tinfoil's inference gateway, sealed with EHBP to a verified replica of the model that the request names. It serves only the models that are pinned to repositories with the `modelPins` option, so at least one pin is required, and a request for any other model fails with a configuration error without contacting a replica. The gateway API may change in a later release.

Its `url` option is the gateway's origin, `https://inference-gateway.tinfoil.sh/` by default, or the URL that the gateway is mounted under, as a proxy URL's path is: the catalog, the attestation relay and an `OpenAIClient`'s API path join under it.

The gateway client verifies each model's replicas separately. Its `ensureVerified(model:)` and `reverify(model:)` take the model, and `reverify(model:)` verifies again the replica that `ensureVerified(model:)` would return for it. When that replica fails with `TinfoilError.attestationError`, its verification is discarded and `reverify(model:)` moves on to the next replica, as `ensureVerified(model:)` then does; when no replica passes or keeps a valid verification, it throws the last failure. `replicas` returns an entry for each replica that the client has tried to verify, with its host, the models requested through it, its trusted reference and pinned model, `current`, which follows `currentVerification`'s rule for that replica, and `lastAttempt`, the replica's last attempt as a `Result`.

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
