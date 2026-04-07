package verity.passport.prover

import org.json.JSONObject
import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.MessageDigest
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

data class CscaEntry(
    val publicKey: ByteArray,
    val subject: String,
    val serial: String,
)

object CscaRegistry {

    fun load(path: String): Map<String, List<CscaEntry>> {
        val json = JSONObject(File(path).readText())
        val registry = mutableMapOf<String, List<CscaEntry>>()

        for (country in json.keys()) {
            val entries = json.getJSONArray(country)
            val cscaList = mutableListOf<CscaEntry>()
            for (i in 0 until entries.length()) {
                val entry = entries.getJSONObject(i)
                val pubKeyB64 = entry.getString("public_key")
                val pubKeyBytes = Base64.getDecoder().decode(pubKeyB64)
                cscaList.add(
                    CscaEntry(
                        publicKey = pubKeyBytes,
                        subject = entry.optString("subject", ""),
                        serial = entry.optString("serial", ""),
                    )
                )
            }
            registry[country] = cscaList
        }

        return registry
    }

    /**
     * Find the matching CSCA public key by verifying the CSCA signature
     * over the DSC TBS certificate, matching the Rust pipeline's approach.
     */
    fun findMatchingKey(
        registry: Map<String, List<CscaEntry>>,
        country: String,
        dg1: ByteArray,
        sod: SOD,
    ): ByteArray {
        val entries = registry[country]
            ?: throw PassportError.DataNotFound("No CSCA entries for country: $country")

        // The DSC's TBS certificate bytes and signature from the SOD
        val tbsBytes = sod.certificate.tbs.bytes
        val tbsDigest = MessageDigest.getInstance("SHA-256").digest(tbsBytes)
        val cscaSignatureBytes = sod.certificate.signature

        val errors = mutableListOf<String>()
        for (entry in entries) {
            try {
                // Load the CSCA public key from SubjectPublicKeyInfo (DER)
                val keySpec = X509EncodedKeySpec(entry.publicKey)
                val keyFactory = KeyFactory.getInstance("RSA")
                val publicKey = keyFactory.generatePublic(keySpec)

                // Verify: CSCA signed the DSC TBS certificate
                val sig = Signature.getInstance("SHA256withRSA")
                sig.initVerify(publicKey)
                sig.update(tbsBytes)

                if (sig.verify(cscaSignatureBytes)) {
                    return entry.publicKey
                } else {
                    errors.add("serial=${entry.serial}: signature mismatch")
                }
            } catch (e: Exception) {
                errors.add("serial=${entry.serial}: ${e.message}")
            }
        }

        throw PassportError.DataNotFound(
            "No matching CSCA key found for $country. Tried ${entries.size} keys:\n  " +
                errors.joinToString("\n  ")
        )
    }
}
