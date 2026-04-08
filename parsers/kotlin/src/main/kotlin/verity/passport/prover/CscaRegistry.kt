package verity.passport.prover

import org.json.JSONObject
import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.MessageDigest
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

public data class CscaEntry(
    val publicKey: ByteArray,
    val subject: String,
    val serial: String,
)

/**
 * Registry for CSCA (Country Signing Certificate Authority) public keys,
 * loaded from a JSON file and used to verify DSC certificate signatures.
 */
public object CscaRegistry {

    /**
     * Loads the CSCA registry from a JSON file at [path], returning a map
     * of ISO country codes to their list of known [CscaEntry] public keys.
     */
    public fun load(path: String): Map<String, List<CscaEntry>> {
        val json = JSONObject(File(path).readText())
        return buildMap {
            for (country in json.keys()) {
                val entries = json.getJSONArray(country)
                put(country, buildList {
                    for (i in 0 until entries.length()) {
                        val entry = entries.getJSONObject(i)
                        val pubKeyBytes = Base64.getDecoder().decode(entry.getString("public_key"))
                        add(CscaEntry(
                            publicKey = pubKeyBytes,
                            subject = entry.optString("subject", ""),
                            serial = entry.optString("serial", ""),
                        ))
                    }
                })
            }
        }
    }

    /**
     * Find the matching CSCA public key by verifying the CSCA signature
     * over the DSC TBS certificate, matching the Rust pipeline's approach.
     */
    public fun findMatchingKey(
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
