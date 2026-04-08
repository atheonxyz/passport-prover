// swift-tools-version: 6.0
import Foundation
import PackageDescription

// Modes:
//   source-only (default): Parsing + commitments work. No proving backend.
//   native:                Full proving. Requires local verity repo with built xcframework.
//   release:               Downloads iOS xcframework. Proving on iOS only.

let mode = ProcessInfo.processInfo.environment["VERITY_SWIFT_SDK_MODE"] ?? "source-only"
let verityDir = ProcessInfo.processInfo.environment["VERITY_DIR"]

let verityDep: Package.Dependency
if mode == "native", let dir = verityDir {
    verityDep = .package(path: dir)
} else {
    verityDep = .package(url: "https://github.com/atheonxyz/verity.git", from: "0.3.0")
}

// The executable requires the native ProveKit xcframework to link.
// Only include it when building in native mode.
var products: [Product] = [
    .library(name: "PassportProverLib", targets: ["PassportProverLib"]),
]
var extraTargets: [Target] = []

if mode == "native" {
    products.append(.executable(name: "passport-prover", targets: ["PassportProver"]))
    extraTargets.append(
        .executableTarget(
            name: "PassportProver",
            dependencies: ["PassportProverLib"],
            path: "Sources/PassportProver",
            swiftSettings: [.swiftLanguageMode(.v5)]
        )
    )
}

let package = Package(
    name: "PassportProver",
    platforms: [.macOS(.v13), .iOS(.v15)],
    products: products,
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
        verityDep,
    ],
    targets: [
        .target(
            name: "PassportProverLib",
            dependencies: [
                "BigInt",
                .product(name: "Verity", package: "verity"),
            ],
            path: "Sources/PassportProverLib",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "PassportProverLibTests",
            dependencies: ["PassportProverLib", "BigInt"],
            path: "Tests/PassportProverLibTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ] + extraTargets
)
