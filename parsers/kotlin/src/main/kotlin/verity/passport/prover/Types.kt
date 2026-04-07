package verity.passport.prover

import java.time.Instant

enum class DigestAlgorithm {
    SHA1, SHA224, SHA256, SHA384, SHA512;

    companion object {
        fun fromName(name: String): DigestAlgorithm? = when (name.uppercase().replace("-", "")) {
            "SHA1" -> SHA1
            "SHA224" -> SHA224
            "SHA256" -> SHA256
            "SHA384" -> SHA384
            "SHA512" -> SHA512
            else -> null
        }

        fun fromOid(oid: String): DigestAlgorithm? = when (oid) {
            "1.3.14.3.2.26" -> SHA1
            "2.16.840.1.101.3.4.2.4" -> SHA224
            "2.16.840.1.101.3.4.2.1" -> SHA256
            "2.16.840.1.101.3.4.2.2" -> SHA384
            "2.16.840.1.101.3.4.2.3" -> SHA512
            else -> null
        }
    }
}

enum class SignatureAlgorithmName {
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

    companion object {
        fun fromOid(oid: String): SignatureAlgorithmName? = when (oid) {
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

data class SignatureAlgorithm(
    val name: SignatureAlgorithmName,
    val parameters: ByteArray? = null
)

data class DataGroupHashValues(
    val values: Map<Int, ByteArray>
)

data class EContent(
    val version: Int,
    val hashAlgorithm: DigestAlgorithm,
    val dataGroupHashValues: DataGroupHashValues,
    val bytes: ByteArray
)

data class SignedAttrs(
    val contentType: String,
    val messageDigest: ByteArray,
    val signingTime: Instant?,
    val bytes: ByteArray
)

data class SignerInfo(
    val version: Int,
    val signedAttrs: SignedAttrs,
    val digestAlgorithm: DigestAlgorithm,
    val signatureAlgorithm: SignatureAlgorithm,
    val signature: ByteArray
)

data class SubjectPublicKeyInfo(
    val algorithm: SignatureAlgorithm,
    val subjectPublicKey: ByteArray
)

data class TbsCertificate(
    val version: Int,
    val serialNumber: ByteArray,
    val signatureAlgorithm: SignatureAlgorithm,
    val issuer: String,
    val validityNotBefore: Instant,
    val validityNotAfter: Instant,
    val subject: String,
    val subjectPublicKeyInfo: SubjectPublicKeyInfo,
    val bytes: ByteArray
)

data class DSC(
    val tbs: TbsCertificate,
    val signatureAlgorithm: SignatureAlgorithm,
    val signature: ByteArray
)

data class SOD(
    val version: Int,
    val digestAlgorithms: List<DigestAlgorithm>,
    val encapContentInfo: EContent,
    val signerInfo: SignerInfo,
    val certificate: DSC,
    val bytes: ByteArray
)
