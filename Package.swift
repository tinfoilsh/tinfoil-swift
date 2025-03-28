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
            url: "https://github.com/tinfoilsh/verifier/releases/download/v0.0.25/TinfoilVerifier.xcframework.zip",
            checksum: "4848628ef47a0aa9951cec2381051e3891441f062c099180d9d2f97970a59721"),
        .target(
            name: "TinfoilKit",
            dependencies: [
                .product(name: "OpenAIKit", package: "openai-kit"),
                "TinfoilVerifier"
            ],
            path: "Sources/TinfoilKit")
    ]
)