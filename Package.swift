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
        .package(url: "https://github.com/tinfoilsh/encrypted-http-body-protocol.git", exact: "0.4.2"),
    ],
    targets: [
        .binaryTarget(
            name: "TinfoilGo",
            url: "https://github.com/tinfoilsh/tinfoil-go/releases/download/v0.17.0-rc.9/TinfoilGo.xcframework.zip",
            checksum: "0654847ff374f7d9f3aa286a9cfdb811ec2998f81b2ebd8e2f5ad48ac69ef8f1"),
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
