use anyhow::{Context, Result};
use clap::Parser;
use passport_input_gen::{Binary, PassportReader, SOD};
use passport_prover::{pipeline, FieldHex};
use provekit_common::file;
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "passport-prover")]
#[command(about = "Generate passport proofs (stages 1-4) from DG1 + SOD binary files")]
struct Cli {
    /// Path to the DG1 binary file
    #[arg(long)]
    dg1: PathBuf,

    /// Path to the SOD binary file
    #[arg(long)]
    sod: PathBuf,

    /// Directory containing pre-compiled .pkp prover files
    #[arg(long)]
    pkp_dir: PathBuf,

    /// Blinding factor for DG1 Poseidon commitment (0x-prefixed hex)
    #[arg(long, default_value = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")]
    r_dg1: String,

    /// Minimum age required
    #[arg(long, default_value_t = 18)]
    min_age: u8,

    /// Maximum age required (0 = no upper bound)
    #[arg(long, default_value_t = 0)]
    max_age: u8,

    /// Output directory for proof files (.np format)
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let dg1_bytes = fs::read(&cli.dg1)
        .with_context(|| format!("Failed to read DG1 file: {}", cli.dg1.display()))?;
    let sod_bytes = fs::read(&cli.sod)
        .with_context(|| format!("Failed to read SOD file: {}", cli.sod.display()))?;

    eprintln!("DG1: {} bytes, SOD: {} bytes", dg1_bytes.len(), sod_bytes.len());

    let mut sod_binary = Binary::from_slice(&sod_bytes);
    let sod = SOD::from_der(&mut sod_binary).context("Failed to parse SOD")?;
    eprintln!("SOD parsed (version {})", sod.version);

    let dg1 = Binary::from_slice(&dg1_bytes);
    let reader = PassportReader::new(dg1, sod, false, None);
    let csca_index = reader.validate().context("Passport validation failed")?;
    eprintln!("Passport validated (CSCA key index: {csca_index})");

    let now = chrono::Utc::now().timestamp() as u64;
    let inputs = reader
        .to_circuit_inputs(now, cli.min_age, cli.max_age, csca_index)
        .context("Failed to generate circuit inputs")?;

    let country = std::str::from_utf8(&inputs.dg1[7..10]).unwrap_or("UNK");
    eprintln!("Country: {country}, TBS cert: {} bytes", inputs.passport_validity_contents.dsc_cert_len);

    let r_dg1 = FieldHex::new(&cli.r_dg1).context("Invalid --r_dg1 hex value")?;
    let result = pipeline::run_pipeline(&inputs, &cli.pkp_dir, &r_dg1, now)?;

    eprintln!("\nPipeline complete!");
    eprintln!("  Merkle leaf:        {}", result.leaf);
    eprintln!("  Scoped nullifier:   {}", result.scoped_nullifier);

    if let Some(ref out_dir) = cli.output {
        fs::create_dir_all(out_dir)?;
        file::write(&result.proof_stage1, &out_dir.join("proof_stage1.np"))?;
        file::write(&result.proof_stage2, &out_dir.join("proof_stage2.np"))?;
        file::write(&result.proof_stage3, &out_dir.join("proof_stage3.np"))?;
        file::write(&result.proof_stage4, &out_dir.join("proof_stage4.np"))?;
        eprintln!("Proofs written to {}", out_dir.display());
    }

    println!("{}", result.leaf);
    Ok(())
}
