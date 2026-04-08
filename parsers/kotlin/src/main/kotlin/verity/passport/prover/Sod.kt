package verity.passport.prover

import java.time.Instant

/**
 * The set of data-group hash values stored inside an ePassport's LDS Security Object (SOd).
 * Keys are data-group numbers (e.g. 1 for DG1), values are the raw hash bytes.
 */
public data class DataGroupHashValues(
    val values: Map<Int, ByteArray>,
)

/**
 * The encapsulated content (eContent) of the CMS SignedData structure inside an ePassport SOd.
 * Contains the version, hash algorithm identifier, data-group hashes, and the raw DER bytes.
 */
public data class EContent(
    val version: Int,
    val hashAlgorithm: DigestAlgorithm,
    val dataGroupHashValues: DataGroupHashValues,
    val bytes: ByteArray,
)

/**
 * The signed attributes attached to a CMS SignerInfo, including content type, message digest,
 * optional signing time, and the raw DER encoding used for signature verification.
 */
public data class SignedAttrs(
    val contentType: String,
    val messageDigest: ByteArray,
    val signingTime: Instant?,
    val bytes: ByteArray,
)

/**
 * A CMS SignerInfo structure representing the signer of the ePassport SOd.
 */
public data class SignerInfo(
    val version: Int,
    val signedAttrs: SignedAttrs,
    val digestAlgorithm: DigestAlgorithm,
    val signatureAlgorithm: SignatureAlgorithm,
    val signature: ByteArray,
)

/**
 * The parsed representation of an ePassport Security Object Document (SOd),
 * which is a CMS SignedData structure containing the document hash tree and signer certificate.
 */
public data class SOD(
    val version: Int,
    val digestAlgorithms: List<DigestAlgorithm>,
    val encapContentInfo: EContent,
    val signerInfo: SignerInfo,
    val certificate: DSC,
    val bytes: ByteArray,
)
