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
        .package(url: "https://github.com/tinfoilsh/openai-swift-fork.git", exact: "0.0.11"),
        .package(url: "https://github.com/tinfoilsh/encrypted-http-body-protocol.git", from: "0.3.1"),
    ],
    targets: [
        .binaryTarget(
            name: "Tinfoil",
            url: "https://github.com/tinfoilsh/tinfoil-go/releases/download/v0.15.0/Tinfoil.xcframework.zip",
            checksum: "d81c330f899a42451b8577f9f973d986d64f59996118beff29bf1d26d5de949b"),
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
