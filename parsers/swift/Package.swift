// swift-tools-version: 6.0
import Foundation
import PackageDescription

// For native proving on macOS, the Verity SDK must be a local path dependency
// so it can find the xcframework built by scripts/build-macos.sh.
// Set VERITY_SWIFT_SDK_MODE=native and VERITY_DIR to enable this.
//
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

let package = Package(
    name: "PassportProver",
    platforms: [.macOS(.v13), .iOS(.v15)],
    products: [
        .executable(name: "passport-prover", targets: ["PassportProver"]),
        .library(name: "PassportProverLib", targets: ["PassportProverLib"]),
    ],
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
        .executableTarget(
            name: "PassportProver",
            dependencies: ["PassportProverLib"],
            path: "Sources/PassportProver",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
