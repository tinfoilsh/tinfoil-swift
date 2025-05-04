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
            name: "TinfoilKit",
            targets: ["TinfoilKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/dylanshine/openai-kit.git", from: "1.0.0"),
    ],
    targets: [
        .binaryTarget(
            name: "TinfoilVerifier",
            url: "https://github.com/tinfoilsh/verifier/releases/download/v0.1.4/TinfoilVerifier.xcframework.zip",
            checksum: "876272c3d69e11f3129ede560097aa9572a665b9ac8f33e5bd5951dce5644e1b"),
        .target(
            name: "TinfoilKit",
            dependencies: [
                .product(name: "OpenAIKit", package: "openai-kit"),
                "TinfoilVerifier"
            ],
            path: "Sources/TinfoilKit")
    ]
)