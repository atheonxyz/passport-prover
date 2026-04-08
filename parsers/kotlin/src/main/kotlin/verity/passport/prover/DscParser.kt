package verity.passport.prover

import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.Certificate
import java.time.Instant

/**
 * Parses a Bouncy Castle [Certificate] into the internal [DSC] domain model,
 * extracting all fields needed for ePassport ZK proof generation.
 */
public object DscParser {

    /**
     * Parses a DER-encoded X.509 [Certificate] into a [DSC] containing
     * TBS certificate fields, signature algorithm, and raw signature bytes.
     */
    public fun parse(cert: Certificate): DSC {
        val tbs = cert.tbsCertificate
        val tbsBytes = tbs.getEncoded(ASN1Encoding.DER)

        val version = tbs.version?.intValueExact() ?: 0

        val serialNumber = tbs.serialNumber.value.toByteArray().let { bytes ->
            if (bytes.size > 1 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
        }

        val tbsSigAlg = parseSignatureAlgorithm(tbs.signature)
        val certSigAlg = parseSignatureAlgorithm(cert.signatureAlgorithm)

        val issuer = formatX500Name(tbs.issuer)
        val subject = formatX500Name(tbs.subject)

        val notBefore = parseTime(tbs.startDate)
        val notAfter = parseTime(tbs.endDate)

        val spki = tbs.subjectPublicKeyInfo
        val spkiAlg = parseSignatureAlgorithm(spki.algorithm)
        val publicKeyBytes = spki.publicKeyData.bytes

        val subjectPublicKeyInfo = SubjectPublicKeyInfo(
            algorithm = spkiAlg,
            subjectPublicKey = publicKeyBytes
        )

        val tbsCert = TbsCertificate(
            version = version,
            serialNumber = serialNumber,
            signatureAlgorithm = tbsSigAlg,
            issuer = issuer,
            validityNotBefore = notBefore,
            validityNotAfter = notAfter,
            subject = subject,
            subjectPublicKeyInfo = subjectPublicKeyInfo,
            bytes = tbsBytes
        )

        val signature = cert.signature.bytes

        return DSC(
            tbs = tbsCert,
            signatureAlgorithm = certSigAlg,
            signature = signature
        )
    }

    private fun parseSignatureAlgorithm(algId: org.bouncycastle.asn1.x509.AlgorithmIdentifier): SignatureAlgorithm {
        val name = SignatureAlgorithmName.fromOid(algId.algorithm.id)
            ?: throw PassportError.UnsupportedSignatureAlgorithm(algId.algorithm.id)
        val params = algId.parameters?.toASN1Primitive()?.encoded
        return SignatureAlgorithm(name, params)
    }

    private fun parseTime(time: org.bouncycastle.asn1.x509.Time): Instant {
        return time.date.toInstant()
    }

    private fun formatX500Name(name: org.bouncycastle.asn1.x500.X500Name): String {
        return name.rdNs.flatMap { rdn ->
            rdn.typesAndValues.map { tv ->
                val oid = tv.type.id
                val fieldName = OidRegistry.getName(oid)
                val value = try {
                    tv.value.toASN1Primitive().let { prim ->
                        when (prim) {
                            is ASN1String -> prim.string
                            else -> prim.encoded.toHex()
                        }
                    }
                } catch (e: Exception) {
                    tv.value.toASN1Primitive().encoded.toHex()
                }
                "$fieldName=$value"
            }
        }.joinToString(", ")
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
