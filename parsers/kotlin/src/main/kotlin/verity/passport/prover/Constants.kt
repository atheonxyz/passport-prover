package verity.passport.prover

/** Shared size and domain constants used across ePassport parsing and ZK-proof generation. */
public object Constants {

    /** Maximum byte length of the DER-encoded SignedAttributes structure fed into the ZK circuit. */
    public const val MAX_SIGNED_ATTRIBUTES_SIZE = 200

    /** Maximum byte length of the DER-encoded DG1 (MRZ) data group. */
    public const val MAX_DG1_SIZE = 95

    /** Fixed byte length of an RSA-2048 signature. */
    public const val SIG_BYTES = 256

    /** Maximum byte length of the DER-encoded eContent (LDS Security Object) structure. */
    public const val MAX_ECONTENT_SIZE = 200

    /** Maximum byte length of the DER-encoded TBSCertificate for standard-sized DSCs. */
    public const val MAX_TBS_SIZE = 720

    /** Maximum byte length of the DER-encoded TBSCertificate for larger DSCs (up to 1 300 bytes). */
    public const val MAX_TBS_SIZE_1300 = 1400

    /** Byte length of the first input chunk passed to the ZK circuit hash gadget. */
    public const val CHUNK1_SIZE = 640

    /** Depth of the Merkle tree used for the country-signer certificate registry. */
    public const val TREE_DEPTH = 24

    /** RSA_NE_H domain separator for csc_key_ne_hash. */
    public const val RSA_KEY_NE_HASH_DOMAIN = "0x5253415f4e455f48"

    /** Canonical zero value for a 32-byte field element, used as a placeholder in circuits. */
    public const val ZERO_FIELD = "0x0000000000000000000000000000000000000000000000000000000000000000"
}
