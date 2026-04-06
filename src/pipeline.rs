//! Chains the passport proof pipeline: stage 1 → 2 → 3 → 4.
//!
//! All circuit inputs and proof outputs stay in memory.
//! No TOML files are written. Provers are loaded from pre-compiled
//! .pkp files (no compile/prepare step).

use {
    crate::{input_builder, poseidon2},
    anyhow::{Context, Result},
    ark_ff::{BigInteger, PrimeField},
    noirc_abi::input_parser::Format,
    passport_input_gen::CircuitInputs,
    provekit_common::{file, register_ntt, FieldElement, NoirProof, Prover},
    provekit_prover::Prove,
    std::{path::Path, time::Instant},
};

/// Result of the 4-stage passport proof pipeline.
pub struct PipelineResult {
    pub proof_stage1: NoirProof,
    pub proof_stage2: NoirProof,
    pub proof_stage3: NoirProof,
    pub proof_stage4: NoirProof,
    /// The Merkle leaf output from stage 3 (hex string).
    pub leaf: String,
    /// The scoped nullifier from stage 4 (hex string).
    pub scoped_nullifier: String,
}

/// Convert an ark FieldElement to a 0x-prefixed hex string.
fn field_to_hex(f: &FieldElement) -> String {
    let bigint = f.into_bigint();
    let bytes = bigint.to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}

/// Extract the return value (last public output) from a proof.
fn extract_return_value(proof: &NoirProof) -> &FieldElement {
    proof
        .public_inputs
        .0
        .last()
        .expect("Circuit must have at least one public output")
}

/// Load a pre-compiled Prover from a .pkp file.
fn load_prover(pkp_path: &Path) -> Result<Prover> {
    file::read(pkp_path)
        .with_context(|| format!("Failed to load prover from: {}", pkp_path.display()))
}

/// Parse a JSON input string into an InputMap using the prover's ABI.
fn parse_inputs(prover: &Prover, json_str: &str) -> Result<noirc_abi::InputMap> {
    let abi = prover.witness_generator.abi();
    let format = Format::from_ext("json").context("JSON format not available")?;
    format
        .parse(json_str, abi)
        .context("Failed to parse circuit inputs")
}

/// Run the 4-stage passport proof pipeline.
///
/// # Arguments
/// * `inputs` - Parsed passport data from `passport-input-gen`
/// * `pkp_dir` - Directory containing pre-compiled .pkp files
/// * `r_dg1` - Random blinding factor for DG1 commitment (hex string)
/// * `current_date` - Unix timestamp for age check
pub fn run_pipeline(
    inputs: &CircuitInputs,
    pkp_dir: &Path,
    r_dg1: &str,
    current_date: u64,
) -> Result<PipelineResult> {
    register_ntt();

    let pipeline_start = Instant::now();

    // --- Stage 1: t_add_dsc_1300 ---
    let t = Instant::now();
    eprintln!("[1/4] Loading t_add_dsc_1300.pkp...");
    let prover1 = load_prover(&pkp_dir.join("t_add_dsc_1300-prover.pkp"))?;
    let load_time = t.elapsed();

    let json1 = input_builder::build_stage1_json(inputs);
    let input_map1 = parse_inputs(&prover1, &json1)?;

    let t = Instant::now();
    eprintln!("[1/4] Proving t_add_dsc_1300...");
    let proof1 = prover1.prove(input_map1).context("Stage 1 proving failed")?;
    let prove_time = t.elapsed();
    let comm_out_1 = field_to_hex(extract_return_value(&proof1));
    eprintln!(
        "[1/4] Done in {:.2}s (load {:.2}s). comm_out = {}",
        prove_time.as_secs_f64(),
        load_time.as_secs_f64(),
        &comm_out_1[..18]
    );

    // --- Stage 2: t_add_id_data_1300 ---
    let t = Instant::now();
    eprintln!("[2/4] Loading t_add_id_data_1300.pkp...");
    let prover2 = load_prover(&pkp_dir.join("t_add_id_data_1300-prover.pkp"))?;
    let load_time = t.elapsed();

    let json2 = input_builder::build_stage2_json(inputs, &comm_out_1);
    let input_map2 = parse_inputs(&prover2, &json2)?;

    let t = Instant::now();
    eprintln!("[2/4] Proving t_add_id_data_1300...");
    let proof2 = prover2.prove(input_map2).context("Stage 2 proving failed")?;
    let prove_time = t.elapsed();
    let comm_out_2 = field_to_hex(extract_return_value(&proof2));
    eprintln!(
        "[2/4] Done in {:.2}s (load {:.2}s). comm_out = {}",
        prove_time.as_secs_f64(),
        load_time.as_secs_f64(),
        &comm_out_2[..18]
    );

    // --- Stage 3: t_add_integrity_commit ---
    let t = Instant::now();
    eprintln!("[3/4] Loading t_add_integrity_commit.pkp...");
    let prover3 = load_prover(&pkp_dir.join("t_add_integrity_commit-prover.pkp"))?;
    let load_time = t.elapsed();

    let json3 = input_builder::build_stage3_json(inputs, &comm_out_2, r_dg1);
    let input_map3 = parse_inputs(&prover3, &json3)?;

    let t = Instant::now();
    eprintln!("[3/4] Proving t_add_integrity_commit...");
    let proof3 = prover3
        .prove(input_map3)
        .context("Stage 3 proving failed")?;
    let prove_time = t.elapsed();
    let leaf = field_to_hex(extract_return_value(&proof3));
    eprintln!(
        "[3/4] Done in {:.2}s (load {:.2}s). leaf = {}",
        prove_time.as_secs_f64(),
        load_time.as_secs_f64(),
        &leaf[..18]
    );

    // --- Stage 4: t_attest ---
    // Compute sod_hash and test Merkle root (leaf at index 0, all-zero siblings)
    let sod_hash = poseidon2::compute_sod_hash(&inputs.passport_validity_contents.econtent);
    let sod_hash_hex = poseidon2::field_to_hex_noir(&sod_hash);

    // For testing: compute root from leaf with zero path
    let leaf_field =
        <acir::FieldElement as acir::AcirField>::from_hex(&leaf).expect("valid leaf hex");
    let test_root = poseidon2::compute_test_merkle_root(leaf_field);
    let root_hex = poseidon2::field_to_hex_noir(&test_root);

    let t = Instant::now();
    eprintln!("[4/4] Loading t_attest.pkp...");
    let prover4 = load_prover(&pkp_dir.join("t_attest-prover.pkp"))?;
    let load_time = t.elapsed();

    let json4 = input_builder::build_stage4_json(
        inputs,
        r_dg1,
        &sod_hash_hex,
        &root_hex,
        current_date,
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    );
    let input_map4 = parse_inputs(&prover4, &json4)?;

    let t = Instant::now();
    eprintln!("[4/4] Proving t_attest...");
    let proof4 = prover4.prove(input_map4).context("Stage 4 proving failed")?;
    let prove_time = t.elapsed();

    // Stage 4 returns (param_commitment, nullifier_type, scoped_nullifier)
    let public_outputs = &proof4.public_inputs.0;
    let scoped_nullifier = field_to_hex(public_outputs.last().unwrap());
    eprintln!(
        "[4/4] Done in {:.2}s (load {:.2}s). nullifier = {}",
        prove_time.as_secs_f64(),
        load_time.as_secs_f64(),
        &scoped_nullifier[..18]
    );

    let total = pipeline_start.elapsed();
    eprintln!("\nTotal pipeline time: {:.2}s", total.as_secs_f64());

    Ok(PipelineResult {
        proof_stage1: proof1,
        proof_stage2: proof2,
        proof_stage3: proof3,
        proof_stage4: proof4,
        leaf,
        scoped_nullifier,
    })
}
