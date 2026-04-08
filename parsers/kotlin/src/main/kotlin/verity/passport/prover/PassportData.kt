package verity.passport.prover

/**
 * All fields extracted from a parsed ePassport required for ZK proof generation.
 * Produced by [PassportReader.extract].
 */
public data class PassportData(
    val dg1Padded: ByteArray,
    val dg1Len: Int,
    val signedAttrs: ByteArray,
    val signedAttributesSize: Int,
    val econtent: ByteArray,
    val econtentLen: Int,
    val dscModulus: ByteArray,
    val dscExponent: Long,
    val dscBarrett: ByteArray,
    val sodSignature: ByteArray,
    val cscaModulus: ByteArray,
    val cscaExponent: Long,
    val cscaBarrett: ByteArray,
    val cscaSignature: ByteArray,
    val country: String,
    val dg1HashOffset: Int,
    val tbsCertificate720: ByteArray,
    val tbsCertificateLen: Int,
    val dscPubkeyOffset: Int,
    val dscExponentOffset: Int,
)
