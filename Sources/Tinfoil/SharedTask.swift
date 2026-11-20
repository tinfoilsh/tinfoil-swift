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

/// Runs operation in an unstructured task and returns its result, or nil
/// once timeout seconds pass first. The wait doesn't depend on operation
/// cooperating: at the deadline, or when the caller is cancelled, the task
/// is cancelled and left to finish on its own, so that a caller's callback
/// that ignores cancellation can't hold the caller past the deadline. The
/// caller's cancellation is thrown as `CancellationError`.
func untilDeadline<Success: Sendable>(
    _ timeout: TimeInterval,
    _ operation: @escaping @Sendable () async throws -> Success
) async throws -> Success? {
    try Task.checkCancellation()
    let work = Task { try await operation() }
    let results = AsyncThrowingStream<Success?, Error> { continuation in
        let waiter = Task {
            do {
                continuation.yield(try await work.value)
                continuation.finish()
            } catch {
                continuation.finish(throwing: error)
            }
        }
        let timer = Task {
            try? await Task.sleep(nanoseconds: UInt64(max(timeout, 0) * 1_000_000_000))
            continuation.yield(nil)
            continuation.finish()
        }
        continuation.onTermination = { _ in
            work.cancel()
            waiter.cancel()
            timer.cancel()
        }
    }
    for try await result in results {
        try Task.checkCancellation()
        return result
    }
    throw CancellationError()
}
