import XCTest
import Tinfoil

/// The code in README.md and MIGRATION.md, kept compiling against the public
/// API. The examples reach the network, so they are type-checked, not run.
final class DocumentationExamplesTests: XCTestCase {
    func testTheExamplesCompile() {
        // Referencing the functions is enough for the compiler to check them.
        _ = [readmeExamples, migrationExamples] as [Any]
    }

    private func readmeExamples(key: String, host: String, trust: Trust, registers: [String]) async throws {
        let client = try await OpenAIClient(apiKey: "YOUR_API_KEY")
        let query = ChatQuery(
            messages: [.user(.init(content: .string("Hello, world!")))],
            model: "gpt-oss-120b"
        )
        let response = try await client.chats(query: query)
        print(response.choices.first?.message.content ?? "No response")

        let enclave = try await EnclaveHTTPClient(enclave: "enclave.example.com", trust: .repo("org/repo@v1.2.3"))
        _ = try OpenAIClient(httpClient: enclave, apiKey: "YOUR_API_KEY")

        let policy = Policy(
            pinnedRegisters: VerifiedFacts.Measurement(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: registers),
            freshnessMaxAge: 3600
        )
        _ = try await EnclaveHTTPClient(enclave: host, trust: trust, options: .init(policy: policy))

        let reported = try await EnclaveHTTPClient(enclave: host, trust: trust, options: .init(
            onVerification: { host, result in
                // Called once for every attempt, outside the client's actors.
                if case .failure(.attestationError(let failure)) = result, let rejected = failure.verificationError {
                    print(host, rejected.report.steps.map { "\($0.layer): \($0.status)" })
                }
            }
        ))
        let report = try await reported.ensureVerified()
        let last = await reported.lastVerification  // the most recent attempt, success or failure
        _ = (report, last)
        let json = try JSONEncoder().encode(report)
        _ = json

        let origin = URL(string: "https://app.example/tinfoil")!
        _ = try await RouterHTTPClient(options: .init(
            transport: .ehbp(proxyURL: origin.appendingPathComponent("proxy")),
            fetchAttestation: .relay(origin),
            fetchRouterList: .relay(origin)
        ))
    }

    private func migrationExamples(key: String) async throws {
        _ = try await OpenAIClient(apiKey: key)
        let proxied = try await EnclaveHTTPClient(
            enclave: "enclave.example.com",
            trust: .repo("org/repo"),
            options: .init(
                transport: .ehbp(proxyURL: URL(string: "https://app.example/tinfoil/proxy")!),
                fetchAttestation: .relay(URL(string: "https://app.example/tinfoil")!)
            )
        )
        _ = try OpenAIClient(httpClient: proxied, apiKey: key)
        let http = try await EnclaveHTTPClient(enclave: "enclave.example.com", trust: .repo("org/repo"))
        _ = try await http.ensureVerified()
        _ = try await http.data(from: URL(string: "/v1/models")!)
        await http.close()
    }
}
