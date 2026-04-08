//! Converts `CircuitInputs` into JSON strings for `noirc_abi` input parsing.

use crate::error::{Error, Result};
use crate::poseidon2;
use crate::types::{AttestConfig, FieldHex, FIELD_HEX_ZERO, SALT_STAGE_1, SALT_STAGE_2};
use passport_input_gen::CircuitInputs;
use serde_json::{json, Value};

fn u8_slice_to_json(s: &[u8]) -> Value {
    Value::Array(s.iter().map(|&b| json!(b.to_string())).collect())
}

/// Stage 1: verify CSCA signature over the DSC certificate.
pub fn build_stage1_json(inputs: &CircuitInputs) -> Result<String> {
    let pvc = &inputs.passport_validity_contents;
    let country = std::str::from_utf8(&inputs.dg1[7..10]).unwrap_or("UNK");

    let csc_key_ne_hash = poseidon2::compute_csc_key_ne_hash(&pvc.csc_pubkey, pvc.csc_rsa_exponent)?;
    let csc_key_ne_hash_hex = poseidon2::field_to_hex(&csc_key_ne_hash);

    let obj = json!({
        "csc_pubkey": u8_slice_to_json(&pvc.csc_pubkey),
        "csc_key_ne_hash": csc_key_ne_hash_hex.as_str(),
        "csc_pubkey_redc_param": u8_slice_to_json(&pvc.csc_barrett_mu),
        "salt": SALT_STAGE_1,
        "country": country,
        "tbs_certificate": u8_slice_to_json(&pvc.dsc_cert),
        "dsc_signature": u8_slice_to_json(&pvc.dsc_cert_signature),
        "exponent": pvc.csc_rsa_exponent.to_string(),
        "tbs_certificate_len": pvc.dsc_cert_len.to_string(),
    });
    serde_json::to_string(&obj).map_err(Error::JsonSerialization)
}

/// Stage 2: verify DSC signature over signed attributes.
pub fn build_stage2_json(inputs: &CircuitInputs, comm_in: &FieldHex) -> Result<String> {
    let pvc = &inputs.passport_validity_contents;
    let exp_offset = inputs.exponent_offset().map_err(|e| Error::Passport(e.to_string()))?;

    let obj = json!({
        "comm_in": comm_in.as_str(),
        "salt_in": SALT_STAGE_1,
        "salt_out": SALT_STAGE_2,
        "dg1": u8_slice_to_json(&inputs.dg1),
        "dsc_pubkey": u8_slice_to_json(&pvc.dsc_pubkey),
        "dsc_pubkey_redc_param": u8_slice_to_json(&pvc.dsc_barrett_mu),
        "dsc_pubkey_offset_in_dsc_cert": pvc.dsc_pubkey_offset_in_dsc_cert.to_string(),
        "exponent": pvc.dsc_rsa_exponent.to_string(),
        "exponent_offset_in_dsc_cert": exp_offset.to_string(),
        "sod_signature": u8_slice_to_json(&pvc.dsc_signature),
        "tbs_certificate": u8_slice_to_json(&pvc.dsc_cert),
        "signed_attributes": u8_slice_to_json(&pvc.signed_attributes),
        "e_content": u8_slice_to_json(&pvc.econtent),
    });
    serde_json::to_string(&obj).map_err(Error::JsonSerialization)
}

/// Stage 3: verify DG1 hash chain, compute Merkle leaf.
pub fn build_stage3_json(
    inputs: &CircuitInputs,
    comm_in: &FieldHex,
    r_dg1: &FieldHex,
) -> Result<String> {
    let pvc = &inputs.passport_validity_contents;

    let private_nullifier =
        poseidon2::compute_private_nullifier(&inputs.dg1, &pvc.econtent, &pvc.dsc_signature)?;
    let private_nullifier_hex = poseidon2::field_to_hex(&private_nullifier);

    let obj = json!({
        "comm_in": comm_in.as_str(),
        "salt_in": SALT_STAGE_2,
        "dg1": u8_slice_to_json(&inputs.dg1),
        "dg1_padded_length": inputs.dg1_padded_length.to_string(),
        "dg1_hash_offset": pvc.dg1_hash_offset.to_string(),
        "signed_attributes": u8_slice_to_json(&pvc.signed_attributes),
        "signed_attributes_size": pvc.signed_attributes_size.to_string(),
        "e_content": u8_slice_to_json(&pvc.econtent),
        "e_content_len": pvc.econtent_len.to_string(),
        "private_nullifier": private_nullifier_hex.as_str(),
        "r_dg1": r_dg1.as_str(),
    });
    serde_json::to_string(&obj).map_err(Error::JsonSerialization)
}

/// Stage 4: age attestation via Merkle inclusion proof.
pub fn build_stage4_json(inputs: &CircuitInputs, config: &AttestConfig) -> Result<String> {
    let zero_path: Vec<Value> = (0..poseidon2::MERKLE_DEPTH)
        .map(|_| json!(FIELD_HEX_ZERO))
        .collect();

    let obj = json!({
        "root": config.root.as_str(),
        "current_date": config.current_date.to_string(),
        "service_scope": config.service_scope.as_str(),
        "service_subscope": config.service_subscope.as_str(),
        "dg1": u8_slice_to_json(&inputs.dg1),
        "r_dg1": config.r_dg1.as_str(),
        "sod_hash": config.sod_hash.as_str(),
        "leaf_index": "0",
        "merkle_path": zero_path,
        "min_age_required": inputs.min_age_required.to_string(),
        "max_age_required": inputs.max_age_required.to_string(),
        "nullifier_secret": config.nullifier_secret.as_str(),
    });
    serde_json::to_string(&obj).map_err(Error::JsonSerialization)
}
