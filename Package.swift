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
        .package(url: "https://github.com/tinfoilsh/encrypted-http-body-protocol.git", exact: "0.4.1"),
    ],
    targets: [
        .binaryTarget(
            name: "TinfoilGo",
            url: "https://github.com/tinfoilsh/tinfoil-go/releases/download/v0.17.0-rc.6/TinfoilGo.xcframework.zip",
            checksum: "5f9c41b3da877e1ad83c0938e0b80250baf59fe5e21afbc97541df007fd62a19"),
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
