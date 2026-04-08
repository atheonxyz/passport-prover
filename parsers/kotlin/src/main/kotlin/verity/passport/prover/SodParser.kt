package verity.passport.prover

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.x509.Certificate
import java.time.Instant

/**
 * Parses raw SOD (Security Object Document) bytes from an ePassport into
 * the internal [SOD] domain model using ASN.1 / CMS structures.
 */
public object SodParser {

    /**
     * Parses the raw SOD bytes (with optional 0x77 length prefix) into a [SOD]
     * containing the encapsulated content, DSC certificate, and signer info.
     */
    public fun parse(rawBytes: ByteArray): SOD {
        val bytes = stripLengthPrefix(rawBytes)

        val contentInfo = try {
            ContentInfo.getInstance(ASN1Sequence.fromByteArray(bytes))
        } catch (e: Exception) {
            throw PassportError.CmsParsingFailed(e.message ?: "Unknown error")
        }

        val signedData = try {
            SignedData.getInstance(contentInfo.content)
        } catch (e: Exception) {
            throw PassportError.CmsParsingFailed(e.message ?: "Failed to parse SignedData")
        }

        val version = signedData.version.intValueExact()

        val digestAlgorithms = signedData.digestAlgorithms.map { algObj ->
            val algId = org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(algObj)
            DigestAlgorithm.fromOid(algId.algorithm.id)
                ?: throw PassportError.Asn1DecodingFailed("Unsupported digest algorithm: ${algId.algorithm.id}")
        }

        val encapContent = parseEncapContent(signedData)
        val certificate = parseCertificate(signedData)
        val signerInfo = parseSignerInfo(signedData)

        return SOD(
            version = version,
            digestAlgorithms = digestAlgorithms,
            encapContentInfo = encapContent,
            signerInfo = signerInfo,
            certificate = certificate,
            bytes = bytes
        )
    }

    private fun stripLengthPrefix(data: ByteArray): ByteArray {
        return if (data.size >= 4 && data[0] == 0x77.toByte() && data[1] == 0x82.toByte()) {
            data.copyOfRange(4, data.size)
        } else {
            data
        }
    }

    private fun parseEncapContent(signedData: SignedData): EContent {
        val encapInfo = signedData.encapContentInfo
        val eContentOctets = encapInfo.content
            ?: throw PassportError.MissingRequiredField("eContent")

        val eContentBytes = eContentOctets.toASN1Primitive().let { prim ->
            when (prim) {
                is ASN1OctetString -> prim.octets
                else -> prim.encoded
            }
        }

        val ldsSecObj = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(eContentBytes))
        val ldsEnum = ldsSecObj.objects

        val ldsVersion = (ldsEnum.nextElement() as ASN1Integer).intValueExact()
        val hashAlgId = org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(ldsEnum.nextElement())
        val hashAlgorithm = DigestAlgorithm.fromOid(hashAlgId.algorithm.id)
            ?: throw PassportError.Asn1DecodingFailed("Unsupported hash algorithm: ${hashAlgId.algorithm.id}")

        val dgHashSeq = ASN1Sequence.getInstance(ldsEnum.nextElement())
        val dgHashValues = buildMap<Int, ByteArray> {
            for (i in 0 until dgHashSeq.size()) {
                val dgHash = ASN1Sequence.getInstance(dgHashSeq.getObjectAt(i))
                val dgNumber = (dgHash.getObjectAt(0) as ASN1Integer).intValueExact()
                val dgHashValue = (dgHash.getObjectAt(1) as ASN1OctetString).octets
                put(dgNumber, dgHashValue)
            }
        }

        return EContent(
            version = ldsVersion,
            hashAlgorithm = hashAlgorithm,
            dataGroupHashValues = DataGroupHashValues(dgHashValues),
            bytes = eContentBytes
        )
    }

    private fun parseCertificate(signedData: SignedData): DSC {
        val certs = signedData.certificates
            ?: throw PassportError.MissingRequiredField("certificates")

        if (certs.size() == 0) {
            throw PassportError.MissingRequiredField("DSC certificate")
        }

        val certObj = certs.getObjectAt(0)
        val cert = Certificate.getInstance(certObj)
        return DscParser.parse(cert)
    }

    private fun parseSignerInfo(signedData: SignedData): SignerInfo {
        val signerInfos = signedData.signerInfos
        if (signerInfos.size() == 0) {
            throw PassportError.DataNotFound("No SignerInfo found")
        }

        val si = org.bouncycastle.asn1.cms.SignerInfo.getInstance(signerInfos.getObjectAt(0))
        val siVersion = si.version.intValueExact()

        val digestAlg = DigestAlgorithm.fromOid(si.digestAlgorithm.algorithm.id)
            ?: throw PassportError.Asn1DecodingFailed("Unsupported digest algorithm: ${si.digestAlgorithm.algorithm.id}")

        val sigAlgName = SignatureAlgorithmName.fromOid(si.digestEncryptionAlgorithm.algorithm.id)
            ?: throw PassportError.UnsupportedSignatureAlgorithm(si.digestEncryptionAlgorithm.algorithm.id)
        val sigAlgParams = si.digestEncryptionAlgorithm.parameters?.toASN1Primitive()?.encoded
        val signatureAlgorithm = SignatureAlgorithm(sigAlgName, sigAlgParams)

        val signature = si.encryptedDigest.octets

        val signedAttrs = parseSignedAttrs(si)

        return SignerInfo(
            version = siVersion,
            signedAttrs = signedAttrs,
            digestAlgorithm = digestAlg,
            signatureAlgorithm = signatureAlgorithm,
            signature = signature
        )
    }

    private fun parseSignedAttrs(si: org.bouncycastle.asn1.cms.SignerInfo): SignedAttrs {
        val attrs = si.authenticatedAttributes
            ?: throw PassportError.MissingRequiredField("signedAttrs")

        var contentType = ""
        var messageDigest: ByteArray? = null
        var signingTime: Instant? = null

        for (i in 0 until attrs.size()) {
            val attr = Attribute.getInstance(attrs.getObjectAt(i))
            val oid = attr.attrType.id

            when (oid) {
                CMSAttributes.contentType.id -> {
                    val oidVal = ASN1ObjectIdentifier.getInstance(attr.attrValues.getObjectAt(0))
                    contentType = OidRegistry.getName(oidVal.id)
                }
                CMSAttributes.messageDigest.id -> {
                    val raw = attr.attrValues.getObjectAt(0)
                    messageDigest = raw.toASN1Primitive().encoded
                }
                CMSAttributes.signingTime.id -> {
                    val timeObj = attr.attrValues.getObjectAt(0)
                    signingTime = when (val prim = timeObj.toASN1Primitive()) {
                        is ASN1UTCTime -> prim.date.toInstant()
                        is ASN1GeneralizedTime -> prim.date.toInstant()
                        else -> null
                    }
                }
            }
        }

        if (messageDigest == null) {
            throw PassportError.MissingRequiredField("messageDigest")
        }

        val signedAttrsEncoded = ASN1Set.getInstance(attrs.toASN1Primitive()).getEncoded(ASN1Encoding.DER)

        return SignedAttrs(
            contentType = contentType,
            messageDigest = messageDigest,
            signingTime = signingTime,
            bytes = signedAttrsEncoded
        )
    }
}
