// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PassportProver",
    platforms: [.macOS(.v13), .iOS(.v15)],
    products: [
        .executable(name: "passport-prover", targets: ["PassportProver"]),
        .library(name: "PassportProverLib", targets: ["PassportProverLib"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
        .package(url: "https://github.com/atheonxyz/verity.git", from: "0.3.0"),
    ],
    targets: [
        .target(
            name: "PassportProverLib",
            dependencies: [
                "BigInt",
                .product(name: "Verity", package: "verity"),
            ],
            path: "Sources/PassportProverLib"
        ),
        .executableTarget(
            name: "PassportProver",
            dependencies: ["PassportProverLib"],
            path: "Sources/PassportProver"
        ),
    ]
)
