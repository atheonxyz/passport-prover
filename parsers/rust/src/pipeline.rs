//! 4-stage passport proof pipeline. All I/O stays in memory.

use crate::error::{Error, Result};
use crate::types::{AttestConfig, FieldHex, Stage};
use crate::{input_builder, poseidon2};
use noirc_abi::input_parser::Format;
use passport_input_gen::CircuitInputs;
use provekit_common::{file, register_ntt, FieldElement, NoirProof, Prover};
use provekit_prover::Prove;
use std::path::Path;
use std::time::Instant;

pub struct PipelineResult {
    pub proof_stage1: NoirProof,
    pub proof_stage2: NoirProof,
    pub proof_stage3: NoirProof,
    pub proof_stage4: NoirProof,
    pub leaf: FieldHex,
    pub scoped_nullifier: FieldHex,
}

fn extract_return_value(proof: &NoirProof) -> Result<&FieldElement> {
    proof.public_inputs.0.last().ok_or(Error::NoPublicOutputs)
}

fn load_prover(pkp_dir: &Path, stage: Stage) -> Result<Prover> {
    let path = pkp_dir.join(stage.pkp_filename());
    file::read(&path).map_err(|e| Error::ProverLoad { path, source: e })
}

fn parse_inputs(prover: &Prover, json_str: &str) -> Result<noirc_abi::InputMap> {
    let abi = prover.witness_generator.abi();
    let format = Format::from_ext("json").ok_or(Error::JsonFormatUnavailable)?;
    format
        .parse(json_str, abi)
        .map_err(|e| Error::InputParse(e.into()))
}

struct StageOutput {
    proof: NoirProof,
    hex: FieldHex,
    raw: FieldElement,
}

fn prove_stage(prover: Prover, stage: Stage, json: &str) -> Result<StageOutput> {
    let label = stage.label();
    let input_map = parse_inputs(&prover, json)?;

    let t = Instant::now();
    eprintln!("{label} Proving...");
    let proof = prover.prove(input_map).map_err(|e| Error::Proving {
        stage: stage.number(),
        source: e,
    })?;
    let prove_time = t.elapsed();

    let raw = *extract_return_value(&proof)?;
    let hex = FieldHex::from(&raw);

    eprintln!(
        "{label} Done in {:.2}s. output = {}",
        prove_time.as_secs_f64(),
        &hex.as_str()[..18.min(hex.as_str().len())]
    );

    Ok(StageOutput { proof, hex, raw })
}

pub fn run_pipeline(
    inputs: &CircuitInputs,
    pkp_dir: &Path,
    r_dg1: &FieldHex,
    current_date: u64,
) -> Result<PipelineResult> {
    register_ntt();

    // Load all provers upfront to eliminate load time from proving measurements.
    let t = Instant::now();
    eprintln!("Loading all provers...");
    let prover1 = load_prover(pkp_dir, Stage::AddDsc)?;
    let prover2 = load_prover(pkp_dir, Stage::AddIdData)?;
    let prover3 = load_prover(pkp_dir, Stage::IntegrityCommit)?;
    let prover4 = load_prover(pkp_dir, Stage::Attest)?;
    eprintln!("All provers loaded in {:.2}s", t.elapsed().as_secs_f64());

    let proving_start = Instant::now();

    let json1 = input_builder::build_stage1_json(inputs)?;
    let s1 = prove_stage(prover1, Stage::AddDsc, &json1)?;

    let json2 = input_builder::build_stage2_json(inputs, &s1.hex)?;
    let s2 = prove_stage(prover2, Stage::AddIdData, &json2)?;

    let json3 = input_builder::build_stage3_json(inputs, &s2.hex, r_dg1)?;
    let s3 = prove_stage(prover3, Stage::IntegrityCommit, &json3)?;

    let sod_hash_field = poseidon2::compute_sod_hash(&inputs.passport_validity_contents.econtent)?;
    let sod_hash = poseidon2::field_to_hex(&sod_hash_field);

    let leaf_as_acir = poseidon2::field_element_to_acir(&s3.raw);
    let test_root = poseidon2::compute_test_merkle_root(leaf_as_acir)?;
    let root = poseidon2::field_to_hex(&test_root);

    let attest_config = AttestConfig::builder()
        .r_dg1(r_dg1.clone())
        .sod_hash(sod_hash)
        .root(root)
        .current_date(current_date)
        .build()?;

    let json4 = input_builder::build_stage4_json(inputs, &attest_config)?;
    let s4 = prove_stage(prover4, Stage::Attest, &json4)?;

    eprintln!("\nTotal proving time: {:.2}s", proving_start.elapsed().as_secs_f64());

    Ok(PipelineResult {
        proof_stage1: s1.proof,
        proof_stage2: s2.proof,
        proof_stage3: s3.proof,
        proof_stage4: s4.proof,
        leaf: s3.hex,
        scoped_nullifier: s4.hex,
    })
}
