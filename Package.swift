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
            url: "https://github.com/tinfoilsh/verifier/releases/download/v0.1.5/TinfoilVerifier.xcframework.zip",
            checksum: "dad2ecb4686e5f2817b2638fd11c810324f2e156ca707de192952e4417d6b582"),
        .target(
            name: "TinfoilKit",
            dependencies: [
                .product(name: "OpenAIKit", package: "openai-kit"),
                "TinfoilVerifier"
            ],
            path: "Sources/TinfoilKit")
    ]
)