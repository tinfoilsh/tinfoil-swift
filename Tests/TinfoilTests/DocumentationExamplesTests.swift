import XCTest
import Tinfoil

/// The code in README.md and MIGRATION.md, kept compiling against the public
/// API. The examples reach the network, so they are type-checked, not run.
final class DocumentationExamplesTests: XCTestCase {
    func testTheExamplesCompile() {
        // Referencing the functions is enough for the compiler to check them.
        _ = [readmeExamples, migrationExamples] as [Any]
    }

    private func readmeExamples(key: String, host: String, repo: String, registers: [String]) async throws {
        let client = try await Client(apiKey: "YOUR_API_KEY")
        let query = ChatQuery(
            messages: [.user(.init(content: .string("Hello, world!")))],
            model: "gpt-oss-120b"
        )
        let response = try await client.chats(query: query)
        print(response.choices.first?.message.content ?? "No response")

        _ = try await EnclaveOpenAIClient(
            enclave: "enclave.example.com",
            repo: "org/repo@v1.2.3",
            apiKey: "YOUR_API_KEY"
        )

        let verifier = try Verifier(
            pinnedRegisters: Verification.Measurement(type: "https://tinfoil.sh/predicate/tdx-guest/v2", registers: registers),
            freshnessMaxAge: 3600
        )
        _ = try await EnclaveOpenAIClient(enclave: host, repo: repo, verifier: verifier, apiKey: key)
    }

    private func migrationExamples(key: String) async throws {
        _ = try await Client(apiKey: key)
        _ = try await EnclaveOpenAIClient(
            enclave: "enclave.example.com",
            repo: "org/repo",
            transportMode: .ehbp,
            baseURL: URL(string: "https://proxy.example.com/v1/")!,
            attestationRelay: "proxy.example.com",
            apiKey: key
        )
        let http = try await EnclaveHTTPClient(enclave: "enclave.example.com", repo: "org/repo")
        _ = try await http.ensureVerified()
        _ = try await http.data(from: URL(string: "/v1/models")!)
        await http.close()
    }
}
