import Foundation

/// Router management utilities for fetching available Tinfoil routers
public enum RouterManager {

    /// Error types for router fetching operations
    public enum RouterError: Error, LocalizedError {
        case networkError(String)
        case invalidResponse
        case noRoutersFound

        public var errorDescription: String? {
            switch self {
            case .networkError(let message):
                return "Failed to fetch routers: \(message)"
            case .invalidResponse:
                return "Invalid response format from router API"
            case .noRoutersFound:
                return "No routers found in the response"
            }
        }
    }

    /// Selects a random router from the provided list
    /// - Parameter routers: Array of router addresses
    /// - Returns: A randomly selected router address
    /// - Throws: RouterError.noRoutersFound if the array is empty
    internal static func selectRouter(from routers: [String]) throws -> String {
        guard !routers.isEmpty else {
            throw RouterError.noRoutersFound
        }
        let randomIndex = Int.random(in: 0..<routers.count)
        return routers[randomIndex]
    }

    /// Fetches the list of available routers from the ATC API
    /// and returns a randomly selected address.
    ///
    /// - Returns: A randomly selected router address
    /// - Throws: RouterError if no routers are found or if the request fails
    public static func fetchRouter() async throws -> String {
        let routersURL = TinfoilConstants.atcRoutersURL

        guard let url = URL(string: routersURL) else {
            throw RouterError.networkError("Invalid URL: \(routersURL)")
        }

        do {
            let (data, response) = try await URLSession.shared.data(from: url)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw RouterError.networkError("Invalid response type")
            }

            guard httpResponse.statusCode == 200 else {
                throw RouterError.networkError("\(httpResponse.statusCode) \(HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode))")
            }

            // Try to decode the response
            let routers: [String]
            do {
                routers = try JSONDecoder().decode([String].self, from: data)
            } catch {
                // Decoding failed - invalid response format
                throw RouterError.invalidResponse
            }

            // Select and return a random router
            return try selectRouter(from: routers)

        } catch let error as RouterError {
            throw error
        } catch {
            throw RouterError.networkError(error.localizedDescription)
        }
    }

    /// Fetches a complete attestation bundle from ATC (single-request mode).
    /// The bundle contains all material needed for verification without additional network calls.
    ///
    /// - Parameter attestationURL: Optional URL to fetch the bundle from. Defaults to ATC attestation endpoint.
    /// - Returns: The complete attestation bundle
    /// - Throws: RouterError if the request fails
    public static func fetchAttestationBundle(
        from attestationURL: String = TinfoilConstants.atcAttestationURL
    ) async throws -> AttestationBundle {
        guard let url = URL(string: attestationURL) else {
            throw RouterError.networkError("Invalid URL: \(attestationURL)")
        }

        do {
            let (data, response) = try await URLSession.shared.data(from: url)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw RouterError.networkError("Invalid response type")
            }

            guard httpResponse.statusCode == 200 else {
                throw RouterError.networkError("Failed to fetch attestation bundle: \(httpResponse.statusCode) \(HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode))")
            }

            do {
                let bundle = try JSONDecoder().decode(AttestationBundle.self, from: data)
                return bundle
            } catch {
                throw RouterError.invalidResponse
            }

        } catch let error as RouterError {
            throw error
        } catch {
            throw RouterError.networkError(error.localizedDescription)
        }
    }
}