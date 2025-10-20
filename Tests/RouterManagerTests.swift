import XCTest
@testable import TinfoilAI

final class RouterManagerTests: XCTestCase {

    func testATCAPIURLIsValid() {
        // Test that the ATC API URL is valid
        XCTAssertNotNil(URL(string: TinfoilConstants.atcAPIURL))
        XCTAssertEqual(TinfoilConstants.atcAPIURL, "https://atc.tinfoil.sh/routers")
    }

    func testRouterErrorDescriptions() {
        let networkError = RouterManager.RouterError.networkError("Connection failed")
        XCTAssertEqual(networkError.errorDescription, "Failed to fetch routers: Connection failed")

        let invalidResponse = RouterManager.RouterError.invalidResponse
        XCTAssertEqual(invalidResponse.errorDescription, "Invalid response format from router API")

        let noRouters = RouterManager.RouterError.noRoutersFound
        XCTAssertEqual(noRouters.errorDescription, "No routers found in the response")
    }

    func testErrorHandlingDistinction() {
        // This test verifies that the error types are distinct and properly categorized
        // Testing that invalidResponse is different from noRoutersFound
        let invalidResponseError = RouterManager.RouterError.invalidResponse
        let noRoutersError = RouterManager.RouterError.noRoutersFound

        // Ensure they have different descriptions
        XCTAssertNotEqual(invalidResponseError.errorDescription, noRoutersError.errorDescription)

        // Test the error cases are distinct
        switch invalidResponseError {
        case .invalidResponse:
            XCTAssertTrue(true, "Should be invalidResponse")
        default:
            XCTFail("Wrong error type")
        }

        switch noRoutersError {
        case .noRoutersFound:
            XCTAssertTrue(true, "Should be noRoutersFound")
        default:
            XCTFail("Wrong error type")
        }
    }

    func testSelectRouterFromList() throws {
        // Test that selectRouter works with valid input
        let routers = ["router1.example.com", "router2.example.com", "router3.example.com"]

        // Test that selection returns one of the provided routers
        let selected = try RouterManager.selectRouter(from: routers)
        XCTAssertTrue(routers.contains(selected), "Selected router should be from the provided list")
    }

    func testSelectRouterFromEmptyList() {
        // Test that selectRouter throws correct error for empty array
        let emptyRouters: [String] = []

        XCTAssertThrowsError(try RouterManager.selectRouter(from: emptyRouters)) { error in
            guard let routerError = error as? RouterManager.RouterError else {
                XCTFail("Expected RouterError but got \(error)")
                return
            }

            if case .noRoutersFound = routerError {
                // Expected error
            } else {
                XCTFail("Expected noRoutersFound error but got \(routerError)")
            }
        }
    }

    func testSelectRouterRandomness() throws {
        // Test that selection has some randomness (statistical test)
        let routers = ["router1", "router2", "router3"]
        var selections = Set<String>()

        // Run multiple selections to verify randomness
        for _ in 0..<100 {
            let selected = try RouterManager.selectRouter(from: routers)
            selections.insert(selected)
        }

        // With 100 iterations and 3 routers, we expect to see at least 2 different selections
        // The probability of selecting the same router 100 times is (1/3)^100 ≈ 0
        XCTAssertGreaterThanOrEqual(selections.count, 2, "Router selection should show randomness")
    }
}