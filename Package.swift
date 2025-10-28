// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "tinfoil-swift",
    platforms: [
        .macOS(.v12),
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "TinfoilAI",
            targets: ["TinfoilAI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/MacPaw/OpenAI.git", branch: "main"),
    ],
    targets: [
        .binaryTarget(
            name: "TinfoilVerifier",
            url: "https://github.com/tinfoilsh/verifier/releases/download/v0.10.2/TinfoilVerifier.xcframework.zip",
            checksum: "618eb81012fec10401f1273300819598a9456c6f1af43dd16ad741381fd0c4f6"),
        .target(
            name: "TinfoilAI",
            dependencies: [
                .product(name: "OpenAI", package: "OpenAI"),
                "TinfoilVerifier"
            ],
            path: "Sources/TinfoilAI",
            linkerSettings: [
                .linkedLibrary("resolv")
            ]),
        .testTarget(
            name: "TinfoilAITests",
            dependencies: [
                "TinfoilAI",
                .product(name: "OpenAI", package: "OpenAI")
            ],
            path: "Tests")
    ]
)
