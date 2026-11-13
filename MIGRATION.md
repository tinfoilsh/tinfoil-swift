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
let client = try await Client(apiKey: key)
```

`Client` has the same OpenAI methods that `TinfoilAI` had (`chats`,
`chatsStream`, `audioCreateSpeechStream`, `createResponse` and the rest), and
`client.openAI` reaches any other method of the OpenAI client.

### `TinfoilAI.create` parameters

| 0.8.x | now |
|---|---|
| `apiKey`, `apiKeyProvider` | the same; one of them is required |
| `TINFOIL_API_KEY` when `apiKey` is nil | no longer read: pass the key |
| `githubRepo` with no enclave (Tinfoil's router) | `Client` or `RouterOpenAIClient`; the router's repository is fixed |
| `githubRepo` with an enclave you name | `EnclaveOpenAIClient(enclave:repo:apiKey:)` |
| `baseURL` (a proxy) and `attestationBundleURL` | `EnclaveOpenAIClient(enclave:repo:transportMode: .ehbp, baseURL:attestationRelay:apiKey:)`, or `RouterOpenAIClient(transportMode: .ehbp, baseURL:attestationRelay:apiKey:)`; see below |
| `parsingOptions`, `customHeaders`, `tinfoilEvents` | the same, on every OpenAI client |
| `userCacheSecret` | the same on `RouterOpenAIClient`, `EnclaveOpenAIClient` and the gateway clients; see "Prompt cache" |
| `onVerification: (VerificationDocument?) -> Void` | `onVerificationResult: (Result<Verification, TinfoilError>) -> Void`, which observes, and `verificationCheck: (Verification) throws -> Void`, which can reject an enclave |

### Proxies and attestation

0.8.x fetched an attestation bundle from `attestationBundleURL` (by default
`https://atc.tinfoil.sh/attestation`). Now each client fetches the enclave's
attestation from the enclave itself, or through the host that you pass as
`attestationRelay`, which forwards attestation requests to it.

To send requests through a proxy, pass its URL as `baseURL` with
`transportMode: .ehbp`: request bodies are sealed to the enclave's attested key,
and requests carry `X-Tinfoil-Enclave-Url` so that the proxy can forward them.
The base URL must be HTTPS (or HTTP on localhost or a loopback address) and
carry no credentials, query or fragment.

```swift
let client = try await EnclaveOpenAIClient(
    enclave: "enclave.example.com",
    repo: "org/repo",
    transportMode: .ehbp,
    baseURL: URL(string: "https://proxy.example.com/v1/")!,
    attestationRelay: "proxy.example.com",
    apiKey: key
)
```

### Transport

0.8.x sealed every request body with EHBP. The clients now pin each TLS
connection to the attested key by default, which protects headers and
requests without a body too. Pass `transportMode: .ehbp` where you need bodies
sealed, as a proxy requires. `Client` uses pinned TLS.

### `SecureClient`

`SecureClient` is replaced by `EnclaveHTTPClient` (an enclave you name) and
`RouterHTTPClient` (Tinfoil's router). Both are verified before their
initializer returns, so there is no separate `verify()`.

| 0.8.x | now |
|---|---|
| `SecureClient(githubRepo:enclaveURL:)` | `try await EnclaveHTTPClient(enclave:repo:)` (the enclave is a host, not a URL) |
| `SecureClient(githubRepo:attestationBundleURL:)` | `try await RouterHTTPClient()`, or `EnclaveHTTPClient(enclave:repo:attestationRelay:)` |
| `verify()` | `ensureVerified()` (valid now, verifying only if needed) or `reverify()` |
| `verificationDocument`, `verifiedGroundTruth` | `current`, a `Verification` |
| `verifiedEnclaveURL` | `enclave` and `baseURL` |
| `get(url:headers:)`, `post(url:headers:body:)` → `SecureResponse` | `data(from:)`, `data(for:)` → `(Data, HTTPURLResponse)` |

### Verification results

`VerificationDocument`, `GroundTruth`, `AttestationResponse`, `Measurement`,
`HardwareMeasurement` and the step states are replaced by one `Verification`:

| 0.8.x | `Verification` |
|---|---|
| `configRepo` | `configRepo` |
| `releaseDigest`, `digest` | `codeDigest` |
| `releaseTag` | `codeTag` (`""` when there is none) |
| `codeMeasurement`, `enclaveMeasurement` | `codeMeasurement`, `enclaveMeasurement` (`Verification.Measurement`) |
| `tlsPublicKey` | `tlsPublicKeyFingerprint` |
| `hpkePublicKey` | `hpkePublicKey` (`""` for a TLS-only enclave) |
| `verifier`, `verifiedAt` | `metadata.verifier`, `metadata.verifiedAt` (a `Date`) |
| `securityVerified`, `steps` | gone: a `Verification` exists only when every check passed |
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
and `VerificationCallback` are no longer public. Send requests of your own with
an HTTP client's `data(for:)`, or with `recoverableBytes(for:)` for a streamed
EHBP response and its session recovery token.

## From the 0.9.0 release candidates

| 0.9.0-rc | now |
|---|---|
| `policy: VerificationPolicy(pinnedRegisters:freshnessMaxAge:)` | `verifier: try Verifier(pinnedRegisters:freshnessMaxAge:)` |
| `onEnclaveVerified`, `EnclaveVerifiedCallback` | `verificationCheck`, `VerificationCheck`; a rejection reads "verification check rejected <host>: <cause>" |
| `RouterHTTPClient`, `RouterOpenAIClient`, `EnclaveOpenAIClient` sealed with EHBP | pinned TLS by default; pass `transportMode: .ehbp` to keep sealing, as a proxy base URL requires |
| `Verification.codeTag: String?`, `hpkePublicKey: String?` | `String`, `""` when absent |
| `Verification.verifiedAt`, `verifier` | `metadata.verifiedAt`, `metadata.verifier` |
| `TINFOIL_API_KEY` read when no key is given | not read: pass `apiKey` or `apiKeyProvider` |
| `localizedDescription` of a `TinfoilError` | now led by the category, as in "configuration error: …"; `message` is the text alone |
| a base URL with `?` or `#` | refused |
| `repo: ""` on `EnclaveHTTPClient` or `EnclaveOpenAIClient`, accepting any config that registry trust authorizes | `repo: nil`; an empty string is refused, so that a missing value can't widen the trust by accident. `repo` on the client is `nil` in that case |

`Verifier` takes every trust option of the verifier: pinned registers, a
freshness bound, config registry IDs, config and freshness signing keys (PEM),
embedded references, and a `configAuthorizer` closure. A verifier that takes the
config from the caller needs an enclave you name; the router refuses it.

The clients, the OpenAI clients included, can now be closed with `close()`,
after which their requests and verifications fail with a configuration error.
The OpenAI clients also take a `timeoutInterval`, 60 seconds by default, for
how long a request may wait for the next bytes of its response.

## Prompt cache

The SDK no longer reads `TINFOIL_USER_CACHE_SECRET` or
`~/.tinfoil/user_cache_secret`. Without a `userCacheSecret`, the router and
gateway clients, and `Client`, use a random secret generated once per process
and shared by its clients, so cache hits are no longer shared across processes
or with other Tinfoil SDKs on the machine. Pass `userCacheSecret` to keep a
stable secret, and set `user_cache_secret` in a request's `extraBody` to scope
the cache to each end user.

## New

- `GatewayHTTPClient` and `GatewayOpenAIClient` send each request through
  Tinfoil's inference gateway, sealed to a verified replica of the model it
  names. They are experimental.
- `Verifier.publicRegistryID`, `ConfigAuthorizer` and `ConfigEndorsement` for
  configs that the caller authorizes.
