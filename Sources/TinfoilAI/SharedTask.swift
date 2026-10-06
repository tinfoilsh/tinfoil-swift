import Foundation

/// Waits for an unstructured task that several callers share, without passing
/// this caller's cancellation on to it. Cancelling the caller ends only its own
/// wait; the task keeps running for the others. AsyncThrowingStream is what
/// makes the individual wait cancellation-aware.
func waitForSharedTask<Success: Sendable>(_ task: Task<Success, Error>) async throws -> Success {
    try Task.checkCancellation()
    let results = AsyncThrowingStream<Success, Error> { continuation in
        Task {
            do {
                continuation.yield(try await task.value)
                continuation.finish()
            } catch {
                continuation.finish(throwing: error)
            }
        }
    }
    for try await result in results {
        try Task.checkCancellation()
        return result
    }
    throw CancellationError()
}
