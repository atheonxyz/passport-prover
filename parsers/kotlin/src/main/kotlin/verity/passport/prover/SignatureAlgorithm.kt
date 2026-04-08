package verity.passport.prover

/**
 * Identifies the signature algorithm used to sign or verify ePassport data.
 * Covers both RSA and ECDSA families, as well as key-type OIDs used in SubjectPublicKeyInfo.
 */
public enum class SignatureAlgorithmName {
    SHA1_WITH_RSA,
    SHA256_WITH_RSA,
    SHA384_WITH_RSA,
    SHA512_WITH_RSA,
    RSASSA_PSS,
    ECDSA_WITH_SHA1,
    ECDSA_WITH_SHA256,
    ECDSA_WITH_SHA384,
    ECDSA_WITH_SHA512,
    RSA_ENCRYPTION,
    EC_PUBLIC_KEY;

    public companion object {
        /**
         * Resolves a [SignatureAlgorithmName] from its ASN.1 OID string.
         * Returns null if the OID is not recognised.
         */
        @JvmStatic
        public fun fromOid(oid: String): SignatureAlgorithmName? = when (oid) {
            "1.2.840.113549.1.1.5" -> SHA1_WITH_RSA
            "1.2.840.113549.1.1.11" -> SHA256_WITH_RSA
            "1.2.840.113549.1.1.12" -> SHA384_WITH_RSA
            "1.2.840.113549.1.1.13" -> SHA512_WITH_RSA
            "1.2.840.113549.1.1.10" -> RSASSA_PSS
            "1.2.840.10045.4.1" -> ECDSA_WITH_SHA1
            "1.2.840.10045.4.3.2" -> ECDSA_WITH_SHA256
            "1.2.840.10045.4.3.3" -> ECDSA_WITH_SHA384
            "1.2.840.10045.4.3.4" -> ECDSA_WITH_SHA512
            "1.2.840.113549.1.1.1" -> RSA_ENCRYPTION
            "1.2.840.10045.2.1" -> EC_PUBLIC_KEY
            else -> null
        }
    }
}

/**
 * A fully-identified signature algorithm, pairing a named algorithm with optional DER-encoded parameters.
 * Used in both SignerInfo and certificate structures.
 */
public data class SignatureAlgorithm(
    val name: SignatureAlgorithmName,
    val parameters: ByteArray? = null,
)
