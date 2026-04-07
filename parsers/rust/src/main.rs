use {
    anyhow::{Context, Result},
    clap::Parser,
    passport_input_gen::{Binary, PassportReader, SOD},
    passport_prover::pipeline,
    provekit_common::file,
    std::{fs, path::PathBuf},
};

#[derive(Parser)]
#[command(name = "passport-prover")]
#[command(about = "Generate passport proofs (stages 1-4) from DG1 + SOD binary files")]
struct Cli {
    /// Path to the DG1 binary file (any ePassport DG1)
    #[arg(long)]
    dg1: PathBuf,

    /// Path to the SOD binary file (any ePassport SOD)
    #[arg(long)]
    sod: PathBuf,

    /// Directory containing pre-compiled .pkp files
    /// (t_add_dsc_1300.pkp, t_add_id_data_1300.pkp, t_add_integrity_commit.pkp)
    #[arg(long)]
    pkp_dir: PathBuf,

    /// Random blinding factor for DG1 Poseidon commitment (0x-prefixed hex).
    #[arg(long, default_value = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")]
    r_dg1: String,

    /// Minimum age required for the age check
    #[arg(long, default_value_t = 18)]
    min_age: u8,

    /// Maximum age required (0 = no upper bound)
    #[arg(long, default_value_t = 0)]
    max_age: u8,

    /// Optional directory to write proof files (.np format)
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Read binary files
    let dg1_bytes = fs::read(&cli.dg1)
        .with_context(|| format!("Failed to read DG1 file: {}", cli.dg1.display()))?;
    let sod_bytes = fs::read(&cli.sod)
        .with_context(|| format!("Failed to read SOD file: {}", cli.sod.display()))?;

    eprintln!(
        "DG1: {} bytes, SOD: {} bytes",
        dg1_bytes.len(),
        sod_bytes.len()
    );

    // Parse SOD
    let mut sod_binary = Binary::from_slice(&sod_bytes);
    let sod = SOD::from_der(&mut sod_binary).context("Failed to parse SOD")?;
    eprintln!("SOD parsed (version {})", sod.version);

    // Create reader and validate
    let dg1 = Binary::from_slice(&dg1_bytes);
    let reader = PassportReader::new(dg1, sod, false, None);

    let csca_index = reader.validate().context("Passport validation failed")?;
    eprintln!("Passport validated (CSCA key index: {})", csca_index);

    // Generate circuit inputs
    let now = chrono::Utc::now().timestamp() as u64;
    let inputs = reader
        .to_circuit_inputs(now, cli.min_age, cli.max_age, csca_index)
        .context("Failed to generate circuit inputs")?;

    let country = std::str::from_utf8(&inputs.dg1[7..10]).unwrap_or("UNK");
    eprintln!(
        "Country: {}, TBS cert: {} bytes",
        country, inputs.passport_validity_contents.dsc_cert_len
    );

    // Run the pipeline
    let result = pipeline::run_pipeline(&inputs, &cli.pkp_dir, &cli.r_dg1, now)?;

    eprintln!("\nPipeline complete!");
    eprintln!("  Merkle leaf:        {}", result.leaf);
    eprintln!("  Scoped nullifier:   {}", result.scoped_nullifier);

    // Optionally write proofs to disk
    if let Some(ref out_dir) = cli.output {
        fs::create_dir_all(out_dir)?;

        let p1 = out_dir.join("proof_stage1.np");
        let p2 = out_dir.join("proof_stage2.np");
        let p3 = out_dir.join("proof_stage3.np");
        let p4 = out_dir.join("proof_stage4.np");

        file::write(&result.proof_stage1, &p1)?;
        file::write(&result.proof_stage2, &p2)?;
        file::write(&result.proof_stage3, &p3)?;
        file::write(&result.proof_stage4, &p4)?;

        eprintln!("Proofs written to {}", out_dir.display());
    }

    // Print leaf to stdout for piping
    println!("{}", result.leaf);

    Ok(())
}
