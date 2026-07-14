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
        .package(url: "https://github.com/tinfoilsh/openai-swift-fork.git", exact: "0.0.9"),
        .package(url: "https://github.com/tinfoilsh/encrypted-http-body-protocol.git", from: "0.2.0"),
    ],
    targets: [
        .binaryTarget(
            name: "Tinfoil",
            url: "https://github.com/tinfoilsh/tinfoil-go/releases/download/v0.14.2/Tinfoil.xcframework.zip",
            checksum: "3d12dadcc1fd0a5614af81a6f39c2a92228fcc213bd77750137261322d2e29a7"),
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
