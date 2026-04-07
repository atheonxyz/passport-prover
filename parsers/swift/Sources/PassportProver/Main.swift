import Foundation
import PassportProverLib

@main
struct PassportProverCLI {
    static func main() throws {
        let args = parseArgs(CommandLine.arguments)

        guard let dg1Path = args["--dg1"] else { exitWithUsage("Missing required argument: --dg1") }
        guard let sodPath = args["--sod"] else { exitWithUsage("Missing required argument: --sod") }
        guard let pkpDir = args["--pkp_dir"] else { exitWithUsage("Missing required argument: --pkp_dir") }

        let rDg1 = args["--r_dg1"] ?? "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        let minAge = Int(args["--min_age"] ?? "") ?? 18
        let maxAge = Int(args["--max_age"] ?? "") ?? 0
        let outputDir = args["--output"]
        let cscaPath = args["--csca"]
        let cscaRegistryPath = args["--csca_registry"]

        // Read input files
        let dg1 = try Data(contentsOf: URL(fileURLWithPath: dg1Path))
        let sodBytes = try Data(contentsOf: URL(fileURLWithPath: sodPath))

        print("Parsing SOD (\(sodBytes.count) bytes)...")
        let sod = try SodParser.parse(rawBytes: sodBytes)

        // Resolve CSCA public key
        let cscaPubKey: Data
        if let cscaPath = cscaPath {
            print("Loading CSCA from file: \(cscaPath)")
            cscaPubKey = try Data(contentsOf: URL(fileURLWithPath: cscaPath))
        } else if let registryPath = cscaRegistryPath {
            let country: String
            if dg1.count >= 10 {
                country = String(data: dg1[dg1.startIndex + 7 ..< dg1.startIndex + 10], encoding: .ascii) ?? "<<<"
            } else {
                country = "<<<"
            }
            print("Loading CSCA registry: \(registryPath)")
            print("Looking up CSCA for country: \(country)")
            let registry = try CscaRegistry.load(path: registryPath)
            cscaPubKey = try CscaRegistry.findMatchingKey(registry: registry, country: country, dg1: dg1, sod: sod)
        } else {
            exitWithUsage("Must provide either --csca or --csca_registry")
        }

        let reader = PassportReader(dg1: dg1, sod: sod, cscaPublicKey: cscaPubKey)

        print("Validating passport data chain...")
        try reader.validate()

        print("Extracting circuit inputs...")
        let passportData = try reader.extract()

        let country = passportData.country
        print("Country: \(country)")

        let currentDate = Int64(Date().timeIntervalSince1970)

        let config = WitnessConfig(
            rDg1: rDg1,
            currentDate: currentDate,
            minAgeRequired: minAge,
            maxAgeRequired: maxAge
        )

        // Run the proving pipeline
        let result = try Pipeline.run(
            pkpDir: pkpDir,
            data: passportData,
            config: config
        )

        // Write proof files if output directory specified and proofs were generated
        if let outputDir = outputDir {
            let fm = FileManager.default
            try fm.createDirectory(atPath: outputDir, withIntermediateDirectories: true)

            try writeProof(dir: outputDir, name: "t_add_dsc_1300.np", data: result.proofStage1)
            try writeProof(dir: outputDir, name: "t_add_id_data_1300.np", data: result.proofStage2)
            try writeProof(dir: outputDir, name: "t_add_integrity_commit.np", data: result.proofStage3)
            try writeProof(dir: outputDir, name: "t_attest.np", data: result.proofStage4)

            print("Proofs written to: \(outputDir)")
        }

        // Print the leaf to stdout for piping
        print(result.leaf)
    }
}

private func parseArgs(_ args: [String]) -> [String: String] {
    var map: [String: String] = [:]
    var i = 1
    while i < args.count {
        let key = args[i]
        if key.hasPrefix("--") && i + 1 < args.count {
            map[key] = args[i + 1]
            i += 2
        } else if key == "-h" || key == "--help" {
            printUsage()
            exit(0)
        } else {
            fputs("Unknown argument: \(key)\n", stderr)
            printUsage()
            exit(1)
        }
    }
    return map
}

private func exitWithUsage(_ message: String) -> Never {
    fputs("Error: \(message)\n", stderr)
    printUsage()
    exit(1)
}

private func printUsage() {
    fputs("""
    Usage: passport-prover [OPTIONS]

    Required:
      --dg1 <path>            Path to DG1 binary file
      --sod <path>            Path to SOD binary file
      --pkp_dir <path>        Directory containing .pkp prover files

    CSCA key (one required):
      --csca <path>           Path to CSCA public key (DER-encoded)
      --csca_registry <path>  Path to CSCA registry JSON (auto-selects by country)

    Optional:
      --r_dg1 <hex>           Random blinding factor for DG1 commitment
      --min_age <int>         Minimum age requirement (default: 18)
      --max_age <int>         Maximum age requirement (default: 0 = no upper bound)
      --output <dir>          Directory to write .np proof files
      -h, --help              Show this help message

    """, stderr)
}

private func writeProof(dir: String, name: String, data: Data) throws {
    let path = (dir as NSString).appendingPathComponent(name)
    try data.write(to: URL(fileURLWithPath: path))
    print("  Wrote \(path) (\(data.count) bytes)")
}
