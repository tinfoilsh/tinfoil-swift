import XCTest
@testable import TinfoilAI

/// Pure-unit coverage for the TinfoilEvent header formatting helper. The
/// integration tests in TinfoilAITests.swift exercise the full create()
/// path, but those require live enclave verification and a network API
/// key; this file pins the header contract in isolation.
final class TinfoilEventTests: XCTestCase {

    func testEmptyEventSetReturnsNilSoHeaderIsOmitted() {
        let value = tinfoilEventsHeaderValue([])
        XCTAssertNil(value, "An empty event set must return nil so callers skip adding the header entirely.")
    }

    func testSingleEventProducesSpecValue() {
        let value = tinfoilEventsHeaderValue([.webSearch])
        XCTAssertEqual(value, "web_search", "The header value must match the spec'd family name exactly.")
    }

    func testAllCasesAreSortedAlphabeticallyForStability() {
        let value = tinfoilEventsHeaderValue(Set(TinfoilEvent.allCases))
        let parts = (value ?? "").split(separator: ",").map(String.init)
        XCTAssertEqual(parts, parts.sorted(), "Header families must be emitted in a stable order so router-side parsing is deterministic.")
    }

    func testHeaderNameMatchesRouterContract() {
        XCTAssertEqual(tinfoilEventsHeader, "X-Tinfoil-Events", "The header name is part of the public contract with the router and must not drift without a coordinated release.")
    }
}
