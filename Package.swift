// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Tinfoil",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "Tinfoil",
            targets: ["TinfoilAI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/tinfoilsh/openai-swift-fork.git", exact: "0.0.3"),
        .package(url: "https://github.com/tinfoilsh/encrypted-http-body-protocol.git", from: "0.1.5"),
    ],
    targets: [
        .binaryTarget(
            name: "Tinfoil",
            url: "https://github.com/tinfoilsh/tinfoil-go/releases/download/v0.12.3/Tinfoil.xcframework.zip",
            checksum: "3e67b7e5cdf92b511cae1c184891619b430bcc83c3e5605172f5d30701b496d7"),
        .target(
            name: "TinfoilAI",
            dependencies: [
                .product(name: "OpenAI", package: "openai-swift-fork"),
                .product(name: "EHBP", package: "encrypted-http-body-protocol"),
                "Tinfoil"
            ],
            path: "Sources/TinfoilAI",
            linkerSettings: [
                .linkedLibrary("resolv")
            ]),
        .testTarget(
            name: "TinfoilAITests",
            dependencies: [
                "TinfoilAI",
                .product(name: "OpenAI", package: "openai-swift-fork")
            ],
            path: "Tests")
    ]
)
