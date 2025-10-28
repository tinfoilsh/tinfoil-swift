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
            url: "https://github.com/tinfoilsh/verifier/releases/download/v0.10.4/TinfoilVerifier.xcframework.zip",
            checksum: "fad3a6236c796d5411798f21dfb9c4940e871a6cc6a285e9a4aad869bdf60f3d"),
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
