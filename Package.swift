// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "tinfoil-swift",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "TinfoilAI",
            targets: ["TinfoilAI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/tinfoilsh/openai-swift-fork.git", exact: "0.0.4"),
        .package(url: "https://github.com/tinfoilsh/encrypted-http-body-protocol.git", from: "0.1.5"),
    ],
    targets: [
        .binaryTarget(
            name: "Tinfoil",
            url: "https://github.com/tinfoilsh/tinfoil-go/releases/download/v0.12.5/Tinfoil.xcframework.zip",
            checksum: "5a86f265bd90ec116f7f7e8b6365d0bf4cde591e31a6e40e394f73b76a727f64"),
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
