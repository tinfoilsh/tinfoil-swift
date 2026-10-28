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
        .package(url: "https://github.com/tinfoilsh/openai-swift-fork.git", exact: "0.0.15"),
        .package(url: "https://github.com/tinfoilsh/encrypted-http-body-protocol.git", exact: "0.4.1"),
    ],
    targets: [
        .binaryTarget(
            name: "Tinfoil",
            url: "https://github.com/tinfoilsh/tinfoil-go/releases/download/v0.17.0-rc.5/Tinfoil.xcframework.zip",
            checksum: "318afea0c98c469a180aaab88a060d6c70ad1f90f1f8ac7dda32a4f4d8326320"),
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
