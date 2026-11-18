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
            name: "Tinfoil",
            targets: ["Tinfoil"]),
    ],
    dependencies: [
        .package(url: "https://github.com/tinfoilsh/openai-swift-fork.git", exact: "0.0.15"),
        .package(url: "https://github.com/tinfoilsh/encrypted-http-body-protocol.git", exact: "0.6.0"),
    ],
    targets: [
        .binaryTarget(
            name: "TinfoilGo",
            url: "https://github.com/tinfoilsh/tinfoil-go/releases/download/v0.17.0-rc.10/TinfoilGo.xcframework.zip",
            checksum: "911e533f4a2f6d0f11dd1dd9f6b7b19df4b6526117d88b2133151171b7e53f48"),
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
                .product(name: "OpenAI", package: "openai-swift-fork")
            ])
    ]
)
