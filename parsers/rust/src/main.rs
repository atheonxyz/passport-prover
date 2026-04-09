use anyhow::{Context, Result};
use clap::Parser;
use passport_input_gen::{Binary, PassportReader, SOD};
use passport_prover::{pipeline, FieldHex};
use provekit_common::file;
use std::{env, fs, path::PathBuf};

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

    /// Path to csca_registry/csca_public_key.json
    #[arg(long)]
    csca_json: PathBuf,

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

    // Resolve all paths before chdir
    let dg1_path = fs::canonicalize(&cli.dg1)
        .with_context(|| format!("DG1 file not found: {}", cli.dg1.display()))?;
    let sod_path = fs::canonicalize(&cli.sod)
        .with_context(|| format!("SOD file not found: {}", cli.sod.display()))?;
    let pkp_dir = fs::canonicalize(&cli.pkp_dir)
        .with_context(|| format!("PKP directory not found: {}", cli.pkp_dir.display()))?;
    let output = cli.output.as_ref().map(|p| {
        fs::create_dir_all(p).ok();
        fs::canonicalize(p).unwrap_or_else(|_| p.clone())
    });

    // passport-input-gen loads csca_registry/csca_public_key.json relative to CWD.
    // Derive the root directory from the provided JSON path.
    let csca_json = fs::canonicalize(&cli.csca_json)
        .with_context(|| format!("CSCA JSON not found: {}", cli.csca_json.display()))?;
    let csca_root = csca_json
        .parent()
        .and_then(|p| p.parent())
        .context("--csca-json must be inside a csca_registry/ directory")?;
    env::set_current_dir(csca_root)
        .with_context(|| format!("Failed to set CSCA root: {}", csca_root.display()))?;

    let dg1_bytes = fs::read(&dg1_path)?;
    let sod_bytes = fs::read(&sod_path)?;

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
    let result = pipeline::run_pipeline(&inputs, &pkp_dir, &r_dg1, now)?;

    eprintln!("\nPipeline complete!");
    eprintln!("  Merkle leaf:        {}", result.leaf);
    eprintln!("  Scoped nullifier:   {}", result.scoped_nullifier);

    if let Some(ref out_dir) = output {
        file::write(&result.proof_stage1, &out_dir.join("proof_stage1.np"))?;
        file::write(&result.proof_stage2, &out_dir.join("proof_stage2.np"))?;
        file::write(&result.proof_stage3, &out_dir.join("proof_stage3.np"))?;
        file::write(&result.proof_stage4, &out_dir.join("proof_stage4.np"))?;
        eprintln!("Proofs written to {}", out_dir.display());
    }

    Ok(())
}
