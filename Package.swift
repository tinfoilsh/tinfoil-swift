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
            name: "TinfoilAI",
            targets: ["TinfoilAI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/MacPaw/OpenAI.git", branch: "main"),
    ],
    targets: [
        .binaryTarget(
            name: "TinfoilVerifier",
            url: "https://github.com/tinfoilsh/verifier/releases/download/v0.10.18/TinfoilVerifier.xcframework.zip",
            checksum: "f47a81adb665e48141c8b669b734a7c34444be7431bb93dc157d0c31562077ba"),
        .target(
            name: "TinfoilAI",
            dependencies: [
                .product(name: "OpenAI", package: "OpenAI"),
                "TinfoilVerifier"
            ],
            path: "Sources/TinfoilAI",
            linkerSettings: [
                .linkedLibrary("resolv")
            ]),
        .testTarget(
            name: "TinfoilAITests",
            dependencies: [
                "TinfoilAI",
                .product(name: "OpenAI", package: "OpenAI")
            ],
            path: "Tests")
    ]
)
