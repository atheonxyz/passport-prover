package verity.passport.prover

/**
 * Identifies the hash/digest algorithm used in ePassport cryptographic operations.
 */
public enum class DigestAlgorithm {
    SHA1, SHA224, SHA256, SHA384, SHA512;

    public companion object {
        /**
         * Resolves a [DigestAlgorithm] from a human-readable algorithm name (e.g. "SHA-256").
         * Returns null if the name is not recognised.
         */
        @JvmStatic
        public fun fromName(name: String): DigestAlgorithm? = when (name.uppercase().replace("-", "")) {
            "SHA1" -> SHA1
            "SHA224" -> SHA224
            "SHA256" -> SHA256
            "SHA384" -> SHA384
            "SHA512" -> SHA512
            else -> null
        }

        /**
         * Resolves a [DigestAlgorithm] from its ASN.1 OID string.
         * Returns null if the OID is not recognised.
         */
        @JvmStatic
        public fun fromOid(oid: String): DigestAlgorithm? = when (oid) {
            "1.3.14.3.2.26" -> SHA1
            "2.16.840.1.101.3.4.2.4" -> SHA224
            "2.16.840.1.101.3.4.2.1" -> SHA256
            "2.16.840.1.101.3.4.2.2" -> SHA384
            "2.16.840.1.101.3.4.2.3" -> SHA512
            else -> null
        }
    }
}
