package verity.passport.prover

import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.pkcs.RSAPublicKey
import verity.passport.prover.Constants.MAX_DG1_SIZE
import verity.passport.prover.Constants.MAX_ECONTENT_SIZE
import verity.passport.prover.Constants.MAX_SIGNED_ATTRIBUTES_SIZE
import verity.passport.prover.Constants.MAX_TBS_SIZE_1300
import verity.passport.prover.Constants.SIG_BYTES
import java.security.MessageDigest

data class PassportData(
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

class PassportReader(
    private val dg1: ByteArray,
    private val sod: SOD,
    private val cscaPublicKey: ByteArray? = null
) {

    fun extract(): PassportData {
        val dg1Padded = fitBytes(dg1, MAX_DG1_SIZE, "DG1")

        val (signedAttrs, signedAttrsSize) = extractSignedAttrs()
        val (econtent, econtentLen, econtentRaw) = extractEcontent()
        val (dscModulus, dscExponent, dscBarrett, sodSignature) = extractDsc()
        val (cscaModulus, cscaExponent, cscaBarrett, cscaSignature) = extractCsca()

        val dg1Hash = MessageDigest.getInstance("SHA-256").digest(dg1)
        val dg1HashOffset = findOffset(econtentRaw, dg1Hash, "DG1 hash in eContent")

        val country = extractCountry()

        val (tbsCert, tbsCertLen, dscPubkeyOffset) = extractDscCert(dscModulus, MAX_TBS_SIZE_1300)

        // Find the exponent value bytes in TBS (minimal big-endian, matching Rust's find_exponent_offset)
        val tbsBytes = sod.certificate.tbs.bytes
        val dscExponentOffset = findExponentOffset(tbsBytes, dscExponent.toInt(), tbsBytes.size)

        return PassportData(
            dg1Padded = dg1Padded,
            dg1Len = dg1.size,
            signedAttrs = signedAttrs,
            signedAttributesSize = signedAttrsSize,
            econtent = econtent,
            econtentLen = econtentLen,
            dscModulus = dscModulus,
            dscExponent = dscExponent,
            dscBarrett = dscBarrett,
            sodSignature = sodSignature,
            cscaModulus = cscaModulus,
            cscaExponent = cscaExponent,
            cscaBarrett = cscaBarrett,
            cscaSignature = cscaSignature,
            country = country,
            dg1HashOffset = dg1HashOffset,
            tbsCertificate720 = tbsCert,
            tbsCertificateLen = tbsCertLen,
            dscPubkeyOffset = dscPubkeyOffset,
            dscExponentOffset = dscExponentOffset,
        )
    }

    fun validate() {
        val dg1Hash = MessageDigest.getInstance("SHA-256").digest(dg1)
        val dg1FromEcontent = sod.encapContentInfo.dataGroupHashValues.values[1]
            ?: throw PassportError.MissingDg1Hash()

        if (!dg1Hash.contentEquals(dg1FromEcontent)) {
            throw PassportError.Dg1HashMismatch()
        }

        val econtentHash = MessageDigest.getInstance("SHA-256").digest(sod.encapContentInfo.bytes)
        var msgDigest = sod.signerInfo.signedAttrs.messageDigest
        if (msgDigest.size > 2 && msgDigest[0] == 0x04.toByte()) {
            msgDigest = msgDigest.copyOfRange(2, msgDigest.size)
        }
        if (!econtentHash.contentEquals(msgDigest)) {
            throw PassportError.EcontentHashMismatch()
        }
    }

    private fun extractSignedAttrs(): Pair<ByteArray, Int> {
        val raw = sod.signerInfo.signedAttrs.bytes
        val padded = fitBytes(raw, MAX_SIGNED_ATTRIBUTES_SIZE, "SignedAttributes")
        return Pair(padded, raw.size)
    }

    private fun extractEcontent(): Triple<ByteArray, Int, ByteArray> {
        val raw = sod.encapContentInfo.bytes
        val padded = fitBytes(raw, MAX_ECONTENT_SIZE, "eContent")
        return Triple(padded, raw.size, raw)
    }

    private fun extractDsc(): DscFields {
        val pubKeyBytes = sod.certificate.tbs.subjectPublicKeyInfo.subjectPublicKey
        val rsaPubKey = RSAPublicKey.getInstance(ASN1Sequence.fromByteArray(pubKeyBytes))

        val modulus = bigIntToFixedBytes(rsaPubKey.modulus, SIG_BYTES, "DSC modulus")
        val exponent = rsaPubKey.publicExponent.toLong()
        val barrett = BarrettReduction.computeFixed(modulus, SIG_BYTES + 1)
        val signature = fitBytes(sod.signerInfo.signature, SIG_BYTES, "SOD signature")

        return DscFields(modulus, exponent, barrett, signature)
    }

    private fun extractCsca(): CscaFields {
        val cscaSize = SIG_BYTES * 2

        if (cscaPublicKey != null) {
            // The CSCA key may be a full SubjectPublicKeyInfo (from registry JSON)
            // or raw RSA public key bytes. Try SPKI first, fall back to raw.
            val rsaPubKey = try {
                val spki = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
                    ASN1Sequence.fromByteArray(cscaPublicKey)
                )
                RSAPublicKey.getInstance(spki.parsePublicKey())
            } catch (_: Exception) {
                RSAPublicKey.getInstance(ASN1Sequence.fromByteArray(cscaPublicKey))
            }
            val modulus = bigIntToFixedBytes(rsaPubKey.modulus, cscaSize, "CSCA modulus")
            val exponent = rsaPubKey.publicExponent.toLong()
            val barrett = BarrettReduction.computeFixed(modulus, cscaSize + 1)
            val signature = fitBytes(sod.certificate.signature, cscaSize, "CSCA signature")
            return CscaFields(modulus, exponent, barrett, signature)
        }

        throw PassportError.DataNotFound(
            "CSCA public key not provided. Pass cscaPublicKey to PassportReader constructor."
        )
    }

    private fun extractCountry(): String = extractCountry(dg1)

    private fun extractDscCert(dscModulus: ByteArray, targetSize: Int): Triple<ByteArray, Int, Int> {
        val tbsBytes = sod.certificate.tbs.bytes
        val padded = fitBytes(tbsBytes, targetSize, "TBS certificate")
        val pubkeyOffset = findOffset(tbsBytes, dscModulus, "DSC modulus in TBS")
        return Triple(padded, tbsBytes.size, pubkeyOffset)
    }

    companion object {
        fun extractCountry(dg1: ByteArray): String {
            return if (dg1.size >= 10) {
                String(dg1, 7, 3, Charsets.US_ASCII)
            } else {
                "<<<"
            }
        }

        fun fitBytes(data: ByteArray, size: Int, label: String): ByteArray {
            if (data.size > size) {
                throw PassportError.BufferOverflow("$label: ${data.size} bytes exceeds buffer $size")
            }
            val result = ByteArray(size)
            data.copyInto(result)
            return result
        }

        fun bigIntToFixedBytes(value: java.math.BigInteger, size: Int, label: String): ByteArray {
            var bytes = value.toByteArray()
            if (bytes.size > 1 && bytes[0] == 0.toByte()) {
                bytes = bytes.copyOfRange(1, bytes.size)
            }
            if (bytes.size > size) {
                throw PassportError.BufferOverflow("$label: ${bytes.size} bytes exceeds $size")
            }
            val result = ByteArray(size)
            bytes.copyInto(result, destinationOffset = size - bytes.size)
            return result
        }

        /**
         * Find the offset of the RSA exponent value bytes within TBS certificate.
         * Matches Rust's find_exponent_offset: searches for minimal big-endian bytes.
         */
        fun findExponentOffset(tbs: ByteArray, exponent: Int, tbsLen: Int): Int {
            val expBe = byteArrayOf(
                ((exponent shr 24) and 0xFF).toByte(),
                ((exponent shr 16) and 0xFF).toByte(),
                ((exponent shr 8) and 0xFF).toByte(),
                (exponent and 0xFF).toByte(),
            )
            // Strip leading zeros (minimal representation)
            val start = expBe.indexOfFirst { it != 0.toByte() }.let { if (it < 0) 3 else it }
            val minimal = expBe.copyOfRange(start, expBe.size)
            return findOffset(tbs.copyOf(tbsLen), minimal, "DSC exponent in TBS")
        }

        fun findOffset(haystack: ByteArray, needle: ByteArray, label: String): Int {
            outer@ for (i in 0..haystack.size - needle.size) {
                for (j in needle.indices) {
                    if (haystack[i + j] != needle[j]) continue@outer
                }
                return i
            }
            throw PassportError.DataNotFound(label)
        }
    }
}

private data class DscFields(
    val modulus: ByteArray,
    val exponent: Long,
    val barrett: ByteArray,
    val signature: ByteArray
)

private data class CscaFields(
    val modulus: ByteArray,
    val exponent: Long,
    val barrett: ByteArray,
    val signature: ByteArray
)
