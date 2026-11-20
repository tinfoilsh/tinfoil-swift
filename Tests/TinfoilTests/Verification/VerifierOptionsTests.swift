import XCTest
import Foundation
@testable import Tinfoil

/// The options JSON that the framework's verifier takes: the config trust
/// and the policy as objects tagged by `type`, one per variant.
final class VerifierOptionsTests: XCTestCase {
    private func json(_ trust: Trust?, _ policy: Policy = Policy()) throws -> String {
        try VerifierOptions(policy: policy).json(trust: trust)
    }

    func testTheConfigTrustIsATaggedObject() throws {
        XCTAssertEqual(try json(nil), #"{"policy":{}}"#)
        XCTAssertEqual(try json(.repo("org/repo")), #"{"policy":{}}"#)
        XCTAssertEqual(try json(.project("org/project")), #"{"policy":{}}"#, "The public registry is the default.")
        XCTAssertEqual(try json(.either(repo: "org/repo", project: "org/project")), #"{"policy":{}}"#)
        XCTAssertEqual(
            try json(.project("org/project", registryIDs: ["https://registry.example"])),
            #"{"config_trust":{"ids":["https:\/\/registry.example"],"type":"registries"},"policy":{}}"#
        )
        XCTAssertEqual(
            try json(.signedBy(keys: ["PEM"], project: "org/project")),
            #"{"config_trust":{"keys_pem":["PEM"],"type":"signing_keys"},"policy":{}}"#
        )
        XCTAssertEqual(
            try json(.embeddedConfig(Data("config".utf8), name: "/org/project/v1")),
            #"{"config_trust":{"bytes":"Y29uZmln","name":"\/org\/project\/v1","type":"embedded_config"},"policy":{}}"#
        )
        XCTAssertEqual(
            try json(.embeddedConfig(Data("config".utf8))),
            #"{"config_trust":{"bytes":"Y29uZmln","type":"embedded_config"},"policy":{}}"#
        )
    }

    func testAConfigAuthorizerTakesThePolicyAlone() throws {
        XCTAssertEqual(try json(.authorizedBy { _ in }), "{}")
        XCTAssertEqual(try json(.authorizedBy { _ in }, Policy(freshnessMaxAge: 1)), #"{"freshness_max_age_ns":1000000000}"#)
    }

    func testThePolicyCarriesTaggedArtifacts() throws {
        XCTAssertEqual(
            try json(nil, Policy(pinnedRegisters: .init(type: "t", registers: ["", "ab"]), freshnessMaxAge: 3600)),
            #"{"policy":{"freshness_max_age_ns":3600000000000,"pinned_registers":{"registers":["","ab"],"type":"t"}}}"#
        )
        XCTAssertEqual(try json(nil, Policy(artifacts: .endorsed())), #"{"policy":{}}"#)
        XCTAssertEqual(
            try json(nil, Policy(artifacts: .endorsed(freshnessKeys: ["PEM"]))),
            #"{"policy":{"artifacts":{"freshness_keys_pem":["PEM"],"type":"endorsed"}}}"#
        )
        XCTAssertEqual(
            try json(nil, Policy(artifacts: .embedded(runtime: Data("rt".utf8)))),
            #"{"policy":{"artifacts":{"runtime":"cnQ=","type":"embedded"}}}"#
        )
        XCTAssertEqual(
            try json(nil, Policy(artifacts: .embedded(runtime: Data("rt".utf8), platform: Data("pf".utf8), freshnessKeys: ["PEM"]))),
            #"{"policy":{"artifacts":{"freshness_keys_pem":["PEM"],"platform":"cGY=","runtime":"cnQ=","type":"embedded"}}}"#
        )
    }
}
