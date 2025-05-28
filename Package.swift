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
        .package(url: "https://github.com/MacPaw/OpenAI.git", branch: "main"),
    ],
    targets: [
        .binaryTarget(
            name: "TinfoilVerifier",
            url: "https://github.com/tinfoilsh/verifier/releases/download/v0.1.5/TinfoilVerifier.xcframework.zip",
            checksum: "dad2ecb4686e5f2817b2638fd11c810324f2e156ca707de192952e4417d6b582"),
        .target(
            name: "TinfoilKit",
            dependencies: [
                .product(name: "OpenAI", package: "OpenAI"),
                "TinfoilVerifier"
            ],
            path: "Sources/TinfoilKit"),
        .testTarget(
            name: "TinfoilKitTests",
            dependencies: [
                "TinfoilKit",
                .product(name: "OpenAI", package: "OpenAI")
            ],
            path: "Tests")
    ]
)