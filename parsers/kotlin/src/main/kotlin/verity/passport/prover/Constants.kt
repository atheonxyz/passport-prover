package verity.passport.prover

object Constants {
    const val MAX_SIGNED_ATTRIBUTES_SIZE = 200
    const val MAX_DG1_SIZE = 95
    const val SIG_BYTES = 256
    const val MAX_ECONTENT_SIZE = 200
    const val MAX_TBS_SIZE = 720
    const val MAX_TBS_SIZE_1300 = 1400
    const val CHUNK1_SIZE = 640
    const val TREE_DEPTH = 24

    /** RSA_NE_H domain separator for csc_key_ne_hash. */
    const val RSA_KEY_NE_HASH_DOMAIN = "0x5253415f4e455f48"

    const val ZERO_FIELD = "0x0000000000000000000000000000000000000000000000000000000000000000"
}
