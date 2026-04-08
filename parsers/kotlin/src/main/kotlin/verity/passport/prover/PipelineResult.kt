package verity.passport.prover

import xyz.atheon.verity.Proof

/**
 * The result of a complete proving pipeline run, containing all four stage proofs
 * along with the Merkle tree leaf and scoped nullifier values.
 */
public data class PipelineResult(
    val proofStage1: Proof,
    val proofStage2: Proof,
    val proofStage3: Proof,
    val proofStage4: Proof,
    val leaf: String,
    val scopedNullifier: String,
)
