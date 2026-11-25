// swift-tools-version:5.9
import Foundation
import PackageDescription

let environment = ProcessInfo.processInfo.environment

// TINFOIL_GO_XCFRAMEWORK, a path relative to this package, builds against a
// TinfoilGo framework that was built locally with tinfoil-go's
// scripts/build-mobile.sh, in place of the released one. TINFOIL_CONFORMANCE=1,
// with a framework that was built with MOBILE_BUILD_TAGS=tinfoil_conformance,
// also compiles the tests that run the conformance vectors through it.
let releasedTinfoilGo = Target.binaryTarget(
    name: "TinfoilGo",
    url: "https://github.com/tinfoilsh/tinfoil-go/releases/download/v0.17.0-rc.13/TinfoilGo.xcframework.zip",
    checksum: "035b4f2744b5b98af00f145029c725caf68177f61f352d76450dc53e9bc2dc6a")
let tinfoilGo: Target = if let path = environment["TINFOIL_GO_XCFRAMEWORK"], !path.isEmpty {
    .binaryTarget(name: "TinfoilGo", path: path)
} else {
    releasedTinfoilGo
}
let testSettings: [SwiftSetting] = environment["TINFOIL_CONFORMANCE"] == "1" ? [.define("TINFOIL_CONFORMANCE")] : []

let package = Package(
    name: "tinfoil-swift",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "Tinfoil",
            targets: ["Tinfoil"]),
    ],
    dependencies: [
        .package(url: "https://github.com/tinfoilsh/openai-swift-fork.git", exact: "0.0.15"),
        .package(url: "https://github.com/tinfoilsh/encrypted-http-body-protocol.git", exact: "0.6.0"),
    ],
    targets: [
        tinfoilGo,
        .target(
            name: "Tinfoil",
            dependencies: [
                .product(name: "OpenAI", package: "openai-swift-fork"),
                .product(name: "EHBP", package: "encrypted-http-body-protocol"),
                "TinfoilGo"
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]),
        .testTarget(
            name: "TinfoilTests",
            dependencies: [
                "Tinfoil",
                "TinfoilGo",
                .product(name: "OpenAI", package: "openai-swift-fork")
            ],
            resources: [
                .copy("Resources/report-json"),
            ],
            swiftSettings: testSettings)
    ]
)
