import XCTest

extension XCTestCase {
    /// Live tests reach Tinfoil's production services. As in the other Tinfoil
    /// SDKs, they run only when RUN_TINFOIL_INTEGRATION=true, and then any
    /// failure, an unreachable service included, fails the test.
    func requireLiveIntegration() throws {
        guard ProcessInfo.processInfo.environment["RUN_TINFOIL_INTEGRATION"] == "true" else {
            throw XCTSkip("Live test; set RUN_TINFOIL_INTEGRATION=true to run it")
        }
    }
}

/// Holds waiters until opened; once open, waits return immediately.
actor AsyncGate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func open() {
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        for waiter in pending {
            waiter.resume()
        }
    }
}
