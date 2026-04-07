//! Converts passport-input-gen's `CircuitInputs` into JSON strings
//! suitable for parsing by `noirc_abi::input_parser::Format`.
//!
//! Each function produces the JSON for one circuit stage, keeping
//! everything in memory (no TOML files written to disk).

use crate::poseidon2;
use passport_input_gen::CircuitInputs;
use serde_json::{json, Value};

/// Find the offset of the RSA exponent value bytes within the TBS certificate.
fn find_exponent_offset(tbs: &[u8], tbs_len: usize, exponent: u32) -> usize {
    let exp_be = exponent.to_be_bytes();
    let start = exp_be.iter().position(|&b| b != 0).unwrap_or(3);
    let exp_minimal = &exp_be[start..];

    for i in 0..tbs_len.saturating_sub(exp_minimal.len()) {
        if &tbs[i..i + exp_minimal.len()] == exp_minimal {
            return i;
        }
    }
    0
}

fn u8_slice_to_json(s: &[u8]) -> Value {
    Value::Array(s.iter().map(|&b| json!(b.to_string())).collect())
}

/// Stage 1: t_add_dsc_1300
///
/// Verifies CSCA signature over the DSC certificate.
/// Computes `csc_key_ne_hash = Poseidon2(domain || pack(csc_pubkey) || pack(exponent))`
/// natively so it matches the circuit's assertion.
pub fn build_stage1_json(inputs: &CircuitInputs) -> String {
    let pvc = &inputs.passport_validity_contents;
    let country = std::str::from_utf8(&inputs.dg1[7..10]).unwrap_or("UNK");

    let csc_key_ne_hash =
        poseidon2::compute_csc_key_ne_hash(&pvc.csc_pubkey, pvc.csc_rsa_exponent);
    let csc_key_ne_hash_hex = poseidon2::field_to_hex_noir(&csc_key_ne_hash);

    let obj = json!({
        "csc_pubkey": u8_slice_to_json(&pvc.csc_pubkey),
        "csc_key_ne_hash": csc_key_ne_hash_hex,
        "csc_pubkey_redc_param": u8_slice_to_json(&pvc.csc_barrett_mu),
        "salt": "0x1",
        "country": country,
        "tbs_certificate": u8_slice_to_json(&pvc.dsc_cert),
        "dsc_signature": u8_slice_to_json(&pvc.dsc_cert_signature),
        "exponent": pvc.csc_rsa_exponent.to_string(),
        "tbs_certificate_len": pvc.dsc_cert_len.to_string(),
    });
    serde_json::to_string(&obj).expect("JSON serialization failed")
}

/// Stage 2: t_add_id_data_1300
///
/// Verifies DSC signature over the passport's signed attributes.
/// `comm_in` is the commitment output from stage 1.
pub fn build_stage2_json(inputs: &CircuitInputs, comm_in: &str) -> String {
    let pvc = &inputs.passport_validity_contents;
    let exp_offset = find_exponent_offset(&pvc.dsc_cert, pvc.dsc_cert_len, pvc.dsc_rsa_exponent);

    let obj = json!({
        "comm_in": comm_in,
        "salt_in": "0x1",
        "salt_out": "0x2",
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
    serde_json::to_string(&obj).expect("JSON serialization failed")
}

/// Stage 3: t_add_integrity_commit
///
/// Verifies the DG1 hash chain and computes the Merkle leaf.
/// `comm_in` is the commitment output from stage 2.
pub fn build_stage3_json(inputs: &CircuitInputs, comm_in: &str, r_dg1: &str) -> String {
    let pvc = &inputs.passport_validity_contents;

    let obj = json!({
        "comm_in": comm_in,
        "salt_in": "0x2",
        "dg1": u8_slice_to_json(&inputs.dg1),
        "dg1_padded_length": inputs.dg1_padded_length.to_string(),
        "dg1_hash_offset": pvc.dg1_hash_offset.to_string(),
        "signed_attributes": u8_slice_to_json(&pvc.signed_attributes),
        "signed_attributes_size": pvc.signed_attributes_size.to_string(),
        "e_content": u8_slice_to_json(&pvc.econtent),
        "e_content_len": pvc.econtent_len.to_string(),
        "private_nullifier": poseidon2::field_to_hex_noir(
            &poseidon2::compute_private_nullifier(
                &inputs.dg1,
                &pvc.econtent,
                &pvc.dsc_signature,
            ),
        ),
        "r_dg1": r_dg1,
    });
    serde_json::to_string(&obj).expect("JSON serialization failed")
}

/// Stage 4: t_attest
///
/// Proves age requirement via Merkle inclusion proof.
/// For testing, `leaf_index = 0` and `merkle_path` is all zeros
/// (root is derived from the leaf with zero siblings).
pub fn build_stage4_json(
    inputs: &CircuitInputs,
    r_dg1: &str,
    sod_hash: &str,
    root: &str,
    current_date: u64,
    service_scope: &str,
    service_subscope: &str,
    nullifier_secret: &str,
) -> String {
    let zero_path: Vec<Value> = (0..24)
        .map(|_| json!("0x0000000000000000000000000000000000000000000000000000000000000000"))
        .collect();

    let obj = json!({
        "root": root,
        "current_date": current_date.to_string(),
        "service_scope": service_scope,
        "service_subscope": service_subscope,
        "dg1": u8_slice_to_json(&inputs.dg1),
        "r_dg1": r_dg1,
        "sod_hash": sod_hash,
        "leaf_index": "0",
        "merkle_path": zero_path,
        "min_age_required": inputs.min_age_required.to_string(),
        "max_age_required": inputs.max_age_required.to_string(),
        "nullifier_secret": nullifier_secret,
    });
    serde_json::to_string(&obj).expect("JSON serialization failed")
}
