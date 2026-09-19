import Foundation
import XCTest

enum VerificationTestSupport {
    static let sevGuestType = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
    static let registerHexLength = 96
    static let liveAttestationVariable = "TINFOIL_RUN_ATTESTATION_INTEGRATION"

    static func requireLiveAttestation() throws {
        guard ProcessInfo.processInfo.environment[liveAttestationVariable] == "1" else {
            throw XCTSkip("Set \(liveAttestationVariable)=1 to run live attestation integration tests")
        }
    }
}
