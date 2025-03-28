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
            url: "https://github.com/tinfoilsh/verifier/releases/download/v0.0.22/TinfoilVerifier.xcframework.zip",
            checksum: "6436a708ecb9b332869d2fa5e8ec2a4a48d3397411bcffeba1dc29c12dcc6c7a"),
        .target(
            name: "TinfoilKit",
            dependencies: [
                .product(name: "OpenAIKit", package: "openai-kit"),
                "TinfoilVerifier"
            ],
            path: "Sources/TinfoilKit")
    ]
)