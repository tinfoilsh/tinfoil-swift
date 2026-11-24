# Migrating to the attestation v3 clients

This release verifies enclaves with Tinfoil's attestation v3 verifier, which
runs inside the bundled TinfoilGo framework, and aligns the Swift clients with
the Go SDK's. Most code changes are mechanical. This guide covers apps on
0.8.x (`TinfoilAI`) and apps on the 0.9.0 release candidates.

## From 0.8.x

### Module and entry point

The module is `Tinfoil`, not `TinfoilAI`, and it re-exports the OpenAI SDK, so
one import is enough.

```swift
// 0.8.x
import TinfoilAI
import OpenAI
let client = try await TinfoilAI.create(apiKey: key)

// Now
import Tinfoil
let client = try await OpenAIClient(apiKey: key)
```

`OpenAIClient` has the same OpenAI methods that `TinfoilAI` had (`chats`,
`chatsStream`, `audioCreateSpeechStream`, `createResponse` and the rest), and
`client.openAI` reaches any other method of the OpenAI client.

### `TinfoilAI.create` parameters

| 0.8.x | now |
|---|---|
| `apiKey`, `apiKeyProvider` | the same; one of them is required |
| `TINFOIL_API_KEY` when `apiKey` is nil | no longer read: pass the key |
| `githubRepo` with no enclave (Tinfoil's router) | `OpenAIClient(apiKey:)`, or `OpenAIClient(httpClient:apiKey:)` over a `RouterHTTPClient`; the router's trust is fixed |
| `githubRepo` with an enclave you name | `OpenAIClient(httpClient:apiKey:)` over `EnclaveHTTPClient(enclave:trust:)` with `trust: .repo("org/repo")` |
| `baseURL` (a proxy) and `attestationBundleURL` | the HTTP client's `options: .init(transport: .ehbp(proxyURL:), fetchAttestation: .relay(_:))`; see below |
| `parsingOptions`, `customHeaders`, `tinfoilEvents` | the same, on `OpenAIClient` |
| `userCacheSecret` | the `userCacheSecret` option of `RouterHTTPClient` and `GatewayHTTPClient`; see "Prompt cache" |
| `onVerification: (VerificationDocument?) -> Void` | `onVerification: (String, Result<VerificationReport, TinfoilError>) -> Void`, which observes each attempt, and `verificationCheck: (VerifiedFacts) throws -> Void`, which can reject an enclave |

### Proxies and attestation

0.8.x fetched an attestation bundle from `attestationBundleURL` (by default
`https://atc.tinfoil.sh/attestation`). Now each client fetches the enclave's
attestation from the enclave itself, or through a relay that you pass as
`fetchAttestation: .relay(url)`, which forwards attestation requests to it.

To send requests through a proxy, pass `transport: .ehbp(proxyURL:)`: request
bodies are sealed to the enclave's attested key, and requests carry
`X-Tinfoil-Enclave-Url` so that the proxy can forward them. The proxy URL must
be HTTPS (or HTTP on localhost or a loopback address) and carry no
credentials, query or fragment. Its path is where the proxy is mounted: the
OpenAI client adds the API path, `/v1/` by default, under it.

```swift
let proxied = try await EnclaveHTTPClient(
    enclave: "enclave.example.com",
    trust: .repo("org/repo"),
    options: .init(
        transport: .ehbp(proxyURL: URL(string: "https://app.example/tinfoil/proxy")!),
        fetchAttestation: .relay(URL(string: "https://app.example/tinfoil")!)
    )
)
let client = try OpenAIClient(httpClient: proxied, apiKey: key)
```

### Transport

0.8.x sealed every request body with EHBP. The clients now pin each TLS
connection to the attested key by default, which protects headers and
requests without a body too. Pass `transport: .ehbp()` where you need bodies
sealed, as a proxy requires. `OpenAIClient(apiKey:)` uses pinned TLS.

### `SecureClient`

`SecureClient` is replaced by `EnclaveHTTPClient` (an enclave you name) and
`RouterHTTPClient` (Tinfoil's router). Both are verified before their
initializer returns, so there is no separate `verify()`.

| 0.8.x | now |
|---|---|
| `SecureClient(githubRepo:enclaveURL:)` | `try await EnclaveHTTPClient(enclave:trust:)` (the enclave is a host, not a URL) |
| `SecureClient(githubRepo:attestationBundleURL:)` | `try await RouterHTTPClient()`, or `try await EnclaveHTTPClient(enclave:trust:options: .init(fetchAttestation: .relay(_:)))` |
| `verify()` | `ensureVerified()` (valid now, verifying only if needed) or `reverify()` |
| `verificationDocument`, `verifiedGroundTruth` | `lastVerification`, a `Result<VerificationReport, TinfoilError>?` |
| `verifiedEnclaveURL` | `enclave` and `baseURL` |
| `get(url:headers:)`, `post(url:headers:body:)` → `SecureResponse` | `data(from:)`, `data(for:)` → `(Data, HTTPURLResponse)` |

### Verification results

`VerificationDocument`, `GroundTruth`, `AttestationResponse`, `Measurement`,
`HardwareMeasurement` and the step states are replaced by a
`VerificationReport`: its `steps`, one for each layer of the verifier, and the
`VerifiedFacts` of a verification that passed:

| 0.8.x | `VerifiedFacts` |
|---|---|
| `configRepo` | `configRepo` |
| `releaseDigest`, `digest` | `codeDigest` |
| `releaseTag` | `codeTag` (`""` when there is none) |
| `codeMeasurement`, `enclaveMeasurement` | `codeMeasurement`, `enclaveMeasurement` (`VerifiedFacts.Measurement`) |
| `tlsPublicKey` | `tlsPublicKeyFingerprint` |
| `hpkePublicKey` | `hpkePublicKey` (`""` for a TLS-only enclave) |
| `verifier`, `verifiedAt` | `metadata.verifier`, `metadata.verifiedAt` (a `Date`), on the report |
| `securityVerified`, `steps` | the report's `steps`; `verifiedFacts` are set only when every step passed |
| — | `freshnessExpiresAt`, `cryptoMaterial`, and `config`, `runtime` and `platform` for a deployment verified from its config |

### Errors

Failures of configuration, of fetching attestation and of verification are a
`TinfoilError`, with one of three cases: `.configurationError`,
`.networkError` and `.attestationError`. An attestation error carries the
verifier's `layer` (envelope, provenance, quote or policy). `message` is the
text alone, and `category` names the case.

Sending a request can also throw other errors: `URLError` for a transport
failure over pinned TLS, `EHBPError` from the EHBP layer (for example a key
that the enclave still rejects after a refresh), `CancellationError` when the
task is cancelled, and the OpenAI SDK's own errors for an API failure.

| 0.8.x | now |
|---|---|
| `TinfoilError.missingAPIKey` | `.configurationError` |
| `TinfoilError.invalidConfiguration` | `.configurationError` |
| `TinfoilError.connectionError` | `.networkError` |
| `VerificationError` | `.attestationError` |

### Low-level types

`EHBPURLSession`, `EHBPURLSessionFactory`, `TinfoilConstants`, `SecureResponse`
and the 0.8.x `VerificationCallback` are no longer public; the
`VerificationCallback` of this release is the type of the `onVerification`
option. Send requests of your own with
an HTTP client's `data(for:)`, or with `recoverableBytes(for:)` for a streamed
EHBP response and its session recovery token.

## From the 0.9.0 release candidates

| 0.9.0-rc | now |
|---|---|
| `policy: VerificationPolicy(pinnedRegisters:freshnessMaxAge:)` | `options: .init(policy: Policy(pinnedRegisters:freshnessMaxAge:))` |
| `onEnclaveVerified`, `EnclaveVerifiedCallback` | `verificationCheck`, `VerificationCheck`; a rejection reads "verification check rejected <host>: <cause>" |
| `RouterHTTPClient`, `RouterOpenAIClient`, `EnclaveOpenAIClient` sealed with EHBP | pinned TLS by default; pass `transport: .ehbp()` to keep sealing, as a proxy requires |
| `Verification.codeTag: String?`, `hpkePublicKey: String?` | `VerifiedFacts.codeTag`, `hpkePublicKey`: `String`, `""` when absent |
| `Verification.verifiedAt`, `verifier` | `VerificationReport.metadata.verifiedAt`, `metadata.verifier` |
| `TINFOIL_API_KEY` read when no key is given | not read: pass `apiKey` or `apiKeyProvider` |
| `localizedDescription` of a `TinfoilError` | now led by the category, as in "configuration error: …"; `message` is the text alone |
| a base URL with `?` or `#` | refused |
| `repo: "org/repo"` on `EnclaveHTTPClient` or `EnclaveOpenAIClient` | `trust: .repo("org/repo")` for a GitHub repository, or `trust: .project("org/project")` for a config registry project; see below |

The clients can now be closed with `close()`, after which their requests and
verifications fail with a configuration error. `OpenAIClient` takes a
`timeoutInterval`, 60 seconds by default, for how long a request may wait for
the next bytes of its response.

### Client configuration (after 0.9.0-rc.6)

The clients take a trust argument, on the enclave client only, and their
optional settings as one options value. Settings that only make sense
together are one value, such as a proxy URL inside `.ehbp(proxyURL:)`, so
the combinations that used to be refused at run time can no longer be
written. Single values, and the gateway's model pins, of which it needs at
least one, are still checked before any network I/O.

| 0.9.0-rc.6 | now |
|---|---|
| labelled options such as `EnclaveHTTPClient(enclave:pin:transportMode:…)` | `EnclaveHTTPClient(enclave:trust:options:)`, `RouterHTTPClient(options:)` and `GatewayHTTPClient(options:)`, with `EnclaveOptions`, `RouterOptions` and `GatewayOptions` |
| `pin: Pin(repo: r)`, `Pin(project: p)`, `Pin(repo: r, project: p)` | `trust: .repo(r)`, `.project(p)`, `.either(repo: r, project: p)` |
| `Verifier(configRegistryIDs: ids)` with `Pin(project: p)` | `.project(p, registryIDs: ids)`; an empty list is refused, and nil trusts the public registry |
| `Verifier(configSigningKeys: k)` | `.signedBy(keys: k, project:)` |
| `Verifier(configAuthorizer: a)` with `Pin.none` | `.authorizedBy(a)` |
| `EmbeddedReferences(config: .bytes(b, name: n))` with `Pin.none` | `.embeddedConfig(b, name: n)`; an embedded config reference is no longer supported |
| `Verifier.publicRegistryID` | `Trust.publicRegistryID` |
| `verifier: try Verifier(pinnedRegisters: r, freshnessMaxAge: a)` | `policy: Policy(pinnedRegisters: r, freshnessMaxAge: a)`; zero, not nil, selects the default age |
| `Verifier(freshnessSigningKeys: k)` | `Policy(artifacts: .endorsed(freshnessKeys: k))` |
| `Verifier(embeddedReferences: .init(runtime: r, platform: p))` | `Policy(artifacts: .embedded(runtime: r, platform: p))` |
| `ModelPin(repo: r, verifier: v)` | `ModelPin(repo: r, policy: p)` |
| `GatewayHTTPClient(baseURL: u)`, `GatewayHTTPClient.defaultBaseURL` | `GatewayHTTPClient(options: .init(url: u))`, `GatewayHTTPClient.defaultURL` |
| `transportMode: .tls` | `transport: .tls`, or unset |
| `transportMode: .ehbp` | `transport: .ehbp()` |
| `transportMode: .ehbp, baseURL: proxy` | `transport: .ehbp(proxyURL: proxy)`; the OpenAI client adds the API path under it, so `https://proxy.example/v1/` becomes `https://proxy.example/` |
| `baseURL` as a path on the enclave's own origin | gone; a proxy URL on the enclave's own origin is refused |
| `EnclaveHTTPClient.pin`, `RouterHTTPClient.pin` | `EnclaveHTTPClient.trust`; the router has none |
| `transportMode` accessor | `transport` |
| `EnclaveOpenAIClient(enclave:pin:…apiKey:)` | `OpenAIClient(httpClient: try await EnclaveHTTPClient(enclave:trust:options:), apiKey:)` |
| `RouterOpenAIClient(…)`, `GatewayOpenAIClient(…)` | `OpenAIClient(httpClient:apiKey:)` over a `RouterHTTPClient` or a `GatewayHTTPClient` |
| `Client(apiKey:)` | `OpenAIClient(apiKey:)` |
| the OpenAI client's base URL from the HTTP client's `baseURL` | set by the SDK: `OpenAIOptions.apiPath`, `/v1/` by default, under the proxy URL or the enclave's origin; the gateway's URL for a gateway client |
| `userCacheSecret` on an enclave client | gone: the enclave client sends bodies as they are; set `user_cache_secret` per request |
| `attestationRelay: "relay.example"`, a host that serves `/.well-known/tinfoil-attestation?nonce=…&enclave=…` | `fetchAttestation: .relay(URL(string: "https://relay.example")!)`, a URL whose path is where the relay is mounted, or `AttestationFetcher { host, nonce in … }` |
| a router client with `attestationRelay`, which skipped discovery and asked the relay for the fallback router | discovery always runs, and fetches every router's document through `fetchAttestation`; set `fetchRouterList: .relay(url)` to fetch the list through `{url}/routers` too |

`OpenAIClient.httpClient` is an `any AttestedHTTPClient`; cast it to the
concrete client for that client's own members.

### Verification reports (after 0.9.0-rc.6)

Verification returns a `VerificationReport`: the steps that the verifier ran,
the `VerifiedFacts` of a verification that passed, and, when the verifier
rejected the document, the `PartialFacts` that the steps before the failure
established. A rejection is still a `TinfoilError.attestationError`; its
`verificationError` carries the verifier's error and the report. This
release needs a TinfoilGo framework that returns the result in schema
version 2, and refuses any other version.

| 0.9.0-rc.6 | now |
|---|---|
| `Verification` | `VerifiedFacts`, the `verifiedFacts` of a `VerificationReport`; `metadata` moved to the report |
| `Verification.Measurement` | `VerifiedFacts.Measurement` |
| `ensureVerified()`, `reverify()`, the gateway's `ensureVerified(model:)` returning a `Verification` | the same calls, returning a `VerificationReport` |
| `current`, the last successful verification, kept after a later failure | `lastVerification`: the most recent attempt, as a `Result<VerificationReport, TinfoilError>?`, so a failure replaces an earlier success |
| `GatewayHTTPClient.current`, with each replica's last successful `verification` | `GatewayHTTPClient.lastVerification`, with each replica tried, failed ones included, and its `lastVerification` attempt |
| `onVerificationResult: (Result<Verification, TinfoilError>) -> Void`, called once per verification run | `onVerification: (String, Result<VerificationReport, TinfoilError>) -> Void`, called once for every attempt, retries and each router that discovery tries included, with the host that the attempt verified |
| `VerificationResultCallback` | `VerificationCallback` |
| `VerificationCheck` receiving a `Verification` | `VerificationCheck` receiving the `VerifiedFacts` |

### Gateway model pins (after 0.9.0-rc.6)

A gateway client serves only the models that it has pins for, and
`models()` lists only those. A request or `ensureVerified(model:)` for any
other model, including one that a catalog refresh adds later, fails with
`TinfoilError.configurationError` and contacts no replica; a model that the
catalog lists without a pin is no longer verified against the catalog's
repository.

| 0.9.0-rc.6 | now |
|---|---|
| `GatewayOptions(modelPins: pins, pinnedModelsOnly: true)` | `GatewayOptions(modelPins: pins)`; `pinnedModelsOnly` is gone |
| `GatewayOptions()` with no pins, serving every model in the catalog | pin each model to serve: `GatewayOptions(modelPins: ["model": ModelPin(repo: "tinfoilsh/repo")])`; `modelPins` is required, and an empty set is refused before any network I/O |
| `policy` for unpinned models and for pins that set none | `policy` for pins that set none; a pin's own `policy` still replaces it entirely |
| `ReplicaVerification.pinnedModel` of `""` for an unpinned model | always the pinned model's name |

## Prompt cache

The SDK no longer reads `TINFOIL_USER_CACHE_SECRET` or
`~/.tinfoil/user_cache_secret`. Without a `userCacheSecret`, the router and
gateway clients, and `OpenAIClient(apiKey:)`, use a random secret generated once per process
and shared by its clients, so cache hits are no longer shared across processes
or with other Tinfoil SDKs on the machine. Pass `userCacheSecret` to keep a
stable secret, and set `user_cache_secret` in a request's `extraBody` to scope
the cache to each end user.

## New

- `GatewayHTTPClient` sends each request through Tinfoil's inference
  gateway, sealed to a verified replica of the model it names. It is
  experimental.
- `Trust.authorizedBy(_:)`, `ConfigAuthorizer` and `ConfigEndorsement` for
  configs that the caller authorizes.
