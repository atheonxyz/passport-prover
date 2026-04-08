package verity.passport.prover

import verity.passport.prover.Constants.TREE_DEPTH
import verity.passport.prover.Constants.ZERO_FIELD

/**
 * Configuration for witness construction and proof generation.
 * Default values provide reasonable testing defaults for all optional parameters.
 */
public data class WitnessConfig(
    val salt1: String = "0x2",
    val salt2: String = "0x3",
    val rDg1: String = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    val currentDate: Long = 1735689600L,
    val minAgeRequired: Int = 18,
    val maxAgeRequired: Int = 0,
    val serviceScope: String = ZERO_FIELD,
    val serviceSubscope: String = ZERO_FIELD,
    val nullifierSecret: String = ZERO_FIELD,
    val merkleRoot: String = ZERO_FIELD,
    val leafIndex: String = "0",
    val merklePath: List<String> = List(TREE_DEPTH) { ZERO_FIELD },
)
