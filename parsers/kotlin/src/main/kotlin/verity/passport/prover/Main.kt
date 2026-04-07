package verity.passport.prover

import java.io.File

fun main(args: Array<String>) {
    val parsed = parseArgs(args)

    val dg1Path = parsed["--dg1"] ?: exitWithUsage("Missing required argument: --dg1")
    val sodPath = parsed["--sod"] ?: exitWithUsage("Missing required argument: --sod")
    val pkpDir = parsed["--pkp_dir"] ?: exitWithUsage("Missing required argument: --pkp_dir")

    val rDg1 = parsed["--r_dg1"] ?: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    val minAge = parsed["--min_age"]?.toIntOrNull() ?: 18
    val maxAge = parsed["--max_age"]?.toIntOrNull() ?: 0
    val outputDir = parsed["--output"]
    val cscaPath = parsed["--csca"]
    val cscaRegistryPath = parsed["--csca_registry"]

    // Read input files
    val dg1 = File(dg1Path).readBytes()
    val sodBytes = File(sodPath).readBytes()

    val sod = SodParser.parse(sodBytes)

    // Resolve CSCA public key
    val cscaPubKey: ByteArray = when {
        cscaPath != null -> File(cscaPath).readBytes()
        cscaRegistryPath != null -> {
            val country = PassportReader.extractCountry(dg1)
            val registry = CscaRegistry.load(cscaRegistryPath)
            CscaRegistry.findMatchingKey(registry, country, dg1, sod)
        }
        else -> exitWithUsage("Must provide either --csca or --csca_registry")
    }

    val reader = PassportReader(dg1, sod, cscaPubKey)
    reader.validate()
    val passportData = reader.extract()

    val currentDate = System.currentTimeMillis() / 1000

    val config = WitnessConfig(
        rDg1 = rDg1,
        currentDate = currentDate,
        minAgeRequired = minAge,
        maxAgeRequired = maxAge,
    )

    // Run the proving pipeline
    val result = Pipeline.run(
        pkpDir = pkpDir,
        data = passportData,
        config = config,
    )

    // Write proof files if output directory specified
    if (outputDir != null) {
        val dir = File(outputDir)
        dir.mkdirs()

        writeProof(dir, "t_add_dsc_1300.np", result.proofStage1.toByteArray())
        writeProof(dir, "t_add_id_data_1300.np", result.proofStage2.toByteArray())
        writeProof(dir, "t_add_integrity_commit.np", result.proofStage3.toByteArray())
        writeProof(dir, "t_attest.np", result.proofStage4.toByteArray())

    }

    println(result.leaf)
}

private fun parseArgs(args: Array<String>): Map<String, String> {
    val map = mutableMapOf<String, String>()
    var i = 0
    while (i < args.size) {
        val key = args[i]
        if (key.startsWith("--") && i + 1 < args.size) {
            map[key] = args[i + 1]
            i += 2
        } else if (key == "-h" || key == "--help") {
            printUsage()
            kotlin.system.exitProcess(0)
        } else {
            System.err.println("Unknown argument: $key")
            printUsage()
            kotlin.system.exitProcess(1)
        }
    }
    return map
}

private fun exitWithUsage(message: String): Nothing {
    System.err.println("Error: $message")
    printUsage()
    kotlin.system.exitProcess(1)
}

private fun printUsage() {
    System.err.println("""
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
    """.trimIndent())
}

private fun writeProof(dir: File, name: String, data: ByteArray) {
    val file = File(dir, name)
    file.writeBytes(data)
}
