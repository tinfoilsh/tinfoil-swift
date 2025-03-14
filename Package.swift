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
        .package(url: "https://github.com/tinfoilsh/verifier-swift.git", exact: "0.0.22")
    ],
    targets: [
        .target(
            name: "TinfoilKit",
            dependencies: [
                .product(name: "OpenAIKit", package: "openai-kit"),
                .product(name: "TinfoilVerifier", package: "verifier-swift")
            ],
            path: "Sources/TinfoilKit")
    ]
)