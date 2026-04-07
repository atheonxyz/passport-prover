//! Native Poseidon2 sponge hash matching Noir's stdlib implementation.
//!
//! Uses `bn254_blackbox_solver::poseidon2_permutation` for the permutation,
//! and implements the sponge construction from `noir_stdlib/src/hash/poseidon2.nr`.

use acir::AcirField;

type F = acir::FieldElement;

const RATE: usize = 3;

fn permutation(state: &mut [F; 4]) {
    let result =
        bn254_blackbox_solver::poseidon2_permutation(state, 4).expect("poseidon2 permutation");
    state.copy_from_slice(&result);
}

/// Noir-compatible Poseidon2 sponge hash.
///
/// Matches `Poseidon2::hash(input, message_size)` from Noir stdlib
/// when `message_size == input.len()` (fixed-length mode).
pub fn poseidon2_hash(input: &[F]) -> F {
    let in_len = input.len();
    // iv = in_len * 2^64
    let two_pow_64 = F::from(1u128 << 64);
    let iv = F::from(in_len as u128) * two_pow_64;

    let mut state: [F; 4] = [F::zero(), F::zero(), F::zero(), iv];
    let mut cache: [F; 3] = [F::zero(); 3];
    let mut cache_size: usize = 0;

    // Absorb
    for &elem in input {
        if cache_size == RATE {
            // Duplex: add cache to state, permute
            for i in 0..RATE {
                state[i] = state[i] + cache[i];
            }
            permutation(&mut state);
            cache = [F::zero(); 3];
            cache[0] = elem;
            cache_size = 1;
        } else {
            cache[cache_size] = elem;
            cache_size += 1;
        }
    }

    // Squeeze: final duplex
    for i in 0..cache_size {
        state[i] = state[i] + cache[i];
    }
    permutation(&mut state);

    state[0]
}

/// Pack big-endian bytes into BN254 field elements, 31 bytes per field.
/// Matches Noir's `pack_be_bytes_into_fields::<NBytes, N, 31>`.
///
/// Noir stores fields in **reverse** order:
///   result[N-1] = first (possibly partial) chunk
///   result[N-2] = second chunk
///   ...
///   result[0]   = last chunk
pub fn pack_be_bytes_into_fields(bytes: &[u8], num_fields: usize) -> Vec<F> {
    let max_field_size: usize = 31;
    let n_bytes = bytes.len();
    let mut result = vec![F::zero(); num_fields];

    let mut k = 0usize;

    // First chunk is partial: size = MAX_FIELD_SIZE - (N * MAX_FIELD_SIZE - NBytes)
    let first_chunk_size = max_field_size - (num_fields * max_field_size - n_bytes);
    let mut limb = F::zero();
    for _ in 0..first_chunk_size {
        limb = limb * F::from(256u128) + F::from(bytes[k] as u128);
        k += 1;
    }
    result[num_fields - 1] = limb;

    // Remaining full chunks
    for i in 1..num_fields {
        let mut limb = F::zero();
        for _ in 0..max_field_size {
            limb = limb * F::from(256u128) + F::from(bytes[k] as u128);
            k += 1;
        }
        result[num_fields - i - 1] = limb;
    }

    result
}

/// Compute `csc_key_ne_hash` matching Noir's `compute_key_ne_hash::<512>`.
///
/// hash_input = [RSA_KEY_NE_HASH_DOMAIN, packed_pubkey[0..17], packed_exponent[0]]
/// Poseidon2::hash(hash_input, 19)
pub fn compute_csc_key_ne_hash(csc_pubkey: &[u8; 512], exponent: u32) -> F {
    let domain = F::from(0x5253415f4e455f48u128); // "RSA_NE_H"
    // (512 + 30) / 31 = 17 fields
    let packed_pubkey = pack_be_bytes_into_fields(csc_pubkey, 17);
    let exp_bytes = exponent.to_be_bytes();
    // (4 + 30) / 31 = 1 field
    let packed_exponent = pack_be_bytes_into_fields(&exp_bytes, 1);

    let mut hash_input = Vec::with_capacity(19);
    hash_input.push(domain);
    hash_input.extend_from_slice(&packed_pubkey);
    hash_input.extend_from_slice(&packed_exponent);

    poseidon2_hash(&hash_input)
}

/// Compute `private_nullifier` matching Noir's `calculate_private_nullifier`.
///
/// private_nullifier = Poseidon2(packed_dg1 ++ packed_econtent ++ packed_sod_sig)
pub fn compute_private_nullifier(dg1: &[u8; 95], econtent: &[u8; 200], sod_sig: &[u8; 256]) -> F {
    // (95+30)/31 = 4, (200+30)/31 = 7, (256+30)/31 = 9 → total 20
    let packed_dg1 = pack_be_bytes_into_fields(dg1, 4);
    let packed_econtent = pack_be_bytes_into_fields(econtent, 7);
    let packed_sod_sig = pack_be_bytes_into_fields(sod_sig, 9);

    let mut input = Vec::with_capacity(20);
    input.extend_from_slice(&packed_dg1);
    input.extend_from_slice(&packed_econtent);
    input.extend_from_slice(&packed_sod_sig);

    poseidon2_hash(&input)
}

/// Compute `sod_hash` matching Noir's `calculate_sod_hash`.
///
/// sod_hash = Poseidon2(packed_econtent)
pub fn compute_sod_hash(econtent: &[u8; 200]) -> F {
    // (200+30)/31 = 7 fields
    let packed = pack_be_bytes_into_fields(econtent, 7);
    poseidon2_hash(&packed)
}

/// Compute the Merkle root for a leaf at index 0 with all-zero siblings.
/// Used for testing when the sequencer hasn't registered the leaf yet.
pub fn compute_test_merkle_root(leaf: F) -> F {
    let mut current = leaf;
    for _ in 0..24 {
        current = poseidon2_hash(&[current, F::zero()]);
    }
    current
}

/// Convert a Noir FieldElement to a 0x-prefixed hex string.
pub fn field_to_hex_noir(f: &F) -> String {
    format!("0x{}", f.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_matches_benchmark() {
        // From benchmark t_attest.toml:
        // sod_hash = 0x237a444692c7c843c43a8c5af58fd9e1ee9f6b4032db7431fb34ff8e9af060fc
        // root = 0x2ff94ac92b298144a71565dfb425cc9562494d5cee33a9d75a782cf9f3197d59
        // r_dg1 = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        // leaf_index = 0, merkle_path = all zeros
        // dg1 = mock passport data

        // Verify that Poseidon2::hash([leaf, 0], 2) chain matches
        // by computing from the known sod_hash + dg1
        let sod_hash_hex = "237a444692c7c843c43a8c5af58fd9e1ee9f6b4032db7431fb34ff8e9af060fc";
        let sod_hash = F::from_hex(sod_hash_hex).unwrap();

        let r_dg1_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let r_dg1 = F::from_hex(r_dg1_hex).unwrap();

        // Mock DG1 from benchmark
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
        let h_dg1 = poseidon2_hash(&h_dg1_input);

        let leaf = poseidon2_hash(&[h_dg1, sod_hash]);
        let root = compute_test_merkle_root(leaf);

        let root_hex = field_to_hex_noir(&root);
        assert_eq!(
            root_hex,
            "0x2ff94ac92b298144a71565dfb425cc9562494d5cee33a9d75a782cf9f3197d59",
            "Merkle root mismatch"
        );
    }

}
