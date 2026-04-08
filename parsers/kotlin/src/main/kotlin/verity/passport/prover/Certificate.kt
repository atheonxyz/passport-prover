package verity.passport.prover

import java.time.Instant

/**
 * The SubjectPublicKeyInfo structure from an X.509 certificate,
 * containing the algorithm identifier and the raw public-key bit string.
 */
public data class SubjectPublicKeyInfo(
    val algorithm: SignatureAlgorithm,
    val subjectPublicKey: ByteArray,
)

/**
 * The TBSCertificate (to-be-signed) portion of an X.509 Document Signer Certificate,
 * along with the raw DER bytes used for signature verification.
 */
public data class TbsCertificate(
    val version: Int,
    val serialNumber: ByteArray,
    val signatureAlgorithm: SignatureAlgorithm,
    val issuer: String,
    val validityNotBefore: Instant,
    val validityNotAfter: Instant,
    val subject: String,
    val subjectPublicKeyInfo: SubjectPublicKeyInfo,
    val bytes: ByteArray,
)

/**
 * A Document Signer Certificate (DSC) as embedded inside an ePassport SOd CMS structure.
 */
public data class DSC(
    val tbs: TbsCertificate,
    val signatureAlgorithm: SignatureAlgorithm,
    val signature: ByteArray,
)
