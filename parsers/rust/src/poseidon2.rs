//! Poseidon2 sponge hash matching `noir_stdlib/src/hash/poseidon2.nr`.

use crate::error::{Error, Result};
use crate::types::FieldHex;
use acir::AcirField;

type F = acir::FieldElement;

const RATE: usize = 3;
pub const MERKLE_DEPTH: usize = 24;
const MAX_FIELD_BYTES: usize = 31;
const RSA_KEY_NE_HASH_DOMAIN: u128 = 0x5253415f4e455f48; // "RSA_NE_H"

fn permutation(state: &mut [F; 4]) -> Result<()> {
    let result =
        bn254_blackbox_solver::poseidon2_permutation(state, 4).map_err(|_| Error::Poseidon2Permutation)?;
    state.copy_from_slice(&result);
    Ok(())
}

pub fn poseidon2_hash(input: &[F]) -> Result<F> {
    let in_len = input.len();
    let two_pow_64 = F::from(1u128 << 64);
    let iv = F::from(in_len as u128) * two_pow_64;

    let mut state: [F; 4] = [F::zero(), F::zero(), F::zero(), iv];
    let mut cache = [F::zero(); RATE];
    let mut cache_size = 0usize;

    for &elem in input {
        if cache_size == RATE {
            for i in 0..RATE {
                state[i] += cache[i];
            }
            permutation(&mut state)?;
            cache = [F::zero(); RATE];
            cache[0] = elem;
            cache_size = 1;
        } else {
            cache[cache_size] = elem;
            cache_size += 1;
        }
    }

    for i in 0..cache_size {
        state[i] += cache[i];
    }
    permutation(&mut state)?;

    Ok(state[0])
}

/// Matches Noir's `pack_be_bytes_into_fields::<NBytes, N, 31>`.
/// Noir stores fields in reverse order: `result[N-1]` = first (partial) chunk.
pub fn pack_be_bytes_into_fields(bytes: &[u8], num_fields: usize) -> Vec<F> {
    debug_assert!(num_fields * MAX_FIELD_BYTES >= bytes.len(), "not enough fields for byte count");
    let n_bytes = bytes.len();
    let mut result = vec![F::zero(); num_fields];
    let mut k = 0usize;

    let first_chunk_size = MAX_FIELD_BYTES - (num_fields * MAX_FIELD_BYTES - n_bytes);
    let mut limb = F::zero();
    for _ in 0..first_chunk_size {
        limb = limb * F::from(256u128) + F::from(bytes[k] as u128);
        k += 1;
    }
    result[num_fields - 1] = limb;

    for i in 1..num_fields {
        let mut limb = F::zero();
        for _ in 0..MAX_FIELD_BYTES {
            limb = limb * F::from(256u128) + F::from(bytes[k] as u128);
            k += 1;
        }
        result[num_fields - i - 1] = limb;
    }

    result
}

/// Matches Noir's `compute_key_ne_hash::<512>`.
pub fn compute_csc_key_ne_hash(csc_pubkey: &[u8; 512], exponent: u32) -> Result<F> {
    let domain = F::from(RSA_KEY_NE_HASH_DOMAIN);
    let packed_pubkey = pack_be_bytes_into_fields(csc_pubkey, 17);
    let packed_exponent = pack_be_bytes_into_fields(&exponent.to_be_bytes(), 1);

    let mut hash_input = Vec::with_capacity(19);
    hash_input.push(domain);
    hash_input.extend_from_slice(&packed_pubkey);
    hash_input.extend_from_slice(&packed_exponent);

    poseidon2_hash(&hash_input)
}

/// Matches Noir's `calculate_private_nullifier`.
pub fn compute_private_nullifier(
    dg1: &[u8; 95],
    econtent: &[u8; 200],
    sod_sig: &[u8; 256],
) -> Result<F> {
    let packed: Vec<F> = [
        pack_be_bytes_into_fields(dg1, 4),
        pack_be_bytes_into_fields(econtent, 7),
        pack_be_bytes_into_fields(sod_sig, 9),
    ]
    .into_iter()
    .flatten()
    .collect();

    poseidon2_hash(&packed)
}

/// Matches Noir's `calculate_sod_hash`.
pub fn compute_sod_hash(econtent: &[u8; 200]) -> Result<F> {
    let packed = pack_be_bytes_into_fields(econtent, 7);
    poseidon2_hash(&packed)
}

/// Merkle root for a leaf at index 0 with all-zero siblings (testing only).
pub fn compute_test_merkle_root(leaf: F) -> Result<F> {
    let mut current = leaf;
    for _ in 0..MERKLE_DEPTH {
        current = poseidon2_hash(&[current, F::zero()])?;
    }
    Ok(current)
}

pub fn field_to_hex(f: &F) -> FieldHex {
    FieldHex::from(f)
}

/// Convert a provekit `FieldElement` to an acir `FieldElement` via big-endian bytes.
pub fn field_element_to_acir(f: &provekit_common::FieldElement) -> F {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    F::from_be_bytes_reduce(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_matches_benchmark() {
        let sod_hash = F::from_hex(
            "237a444692c7c843c43a8c5af58fd9e1ee9f6b4032db7431fb34ff8e9af060fc",
        )
        .unwrap();
        let r_dg1 = F::from_hex(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        )
        .unwrap();

        let dg1: [u8; 95] = [
            97, 91, 95, 31, 88, 80, 60, 85, 84, 79, 68, 79, 69, 60, 60, 74, 79, 72, 78, 60, 77,
            79, 67, 75, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
            60, 60, 60, 60, 60, 60, 60, 76, 56, 57, 56, 57, 48, 50, 67, 51, 54, 85, 84, 79, 48,
            55, 48, 49, 48, 49, 57, 77, 51, 50, 48, 49, 48, 49, 53, 60, 60, 60, 60, 60, 60, 60,
            60, 60, 60, 60, 60, 60, 60, 48, 56, 0, 0,
        ];

        let packed_dg1 = pack_be_bytes_into_fields(&dg1, 4);
        let mut h_dg1_input = vec![r_dg1];
        h_dg1_input.extend_from_slice(&packed_dg1);
        let h_dg1 = poseidon2_hash(&h_dg1_input).unwrap();

        let leaf = poseidon2_hash(&[h_dg1, sod_hash]).unwrap();
        let root = compute_test_merkle_root(leaf).unwrap();

        let root_hex = field_to_hex(&root);
        assert_eq!(
            root_hex.as_str(),
            "0x2ff94ac92b298144a71565dfb425cc9562494d5cee33a9d75a782cf9f3197d59",
        );
    }
}
