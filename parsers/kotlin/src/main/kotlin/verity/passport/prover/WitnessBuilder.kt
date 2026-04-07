package verity.passport.prover

import org.json.JSONArray
import org.json.JSONObject
import verity.passport.prover.Constants.RSA_KEY_NE_HASH_DOMAIN
import verity.passport.prover.Constants.TREE_DEPTH
import verity.passport.prover.Constants.ZERO_FIELD
import java.math.BigInteger

data class WitnessConfig(
    val salt1: String = "0x2",
    val salt2: String = "0x3",
    val rDg1: String = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    val currentDate: Long = 1735689600L,
    val minAgeRequired: Int = 18,
    val maxAgeRequired: Int = 0,
    val serviceScope: String = ZERO_FIELD,
    val serviceSubscope: String = ZERO_FIELD,
    val nullifierSecret: String = ZERO_FIELD,
    val merkleRoot: String = ZERO_FIELD,
    val leafIndex: String = "0",
    val merklePath: List<String> = List(TREE_DEPTH) { ZERO_FIELD },
)

object WitnessBuilder {

    // =========================================================================
    // Serialization
    // =========================================================================

    fun toJson(witness: Map<String, Any>): String {
        return toJsonObject(witness).toString(2)
    }

    private fun toJsonObject(map: Map<String, Any>): JSONObject {
        val obj = JSONObject()
        for ((key, value) in map) {
            when (value) {
                is Map<*, *> -> {
                    @Suppress("UNCHECKED_CAST")
                    obj.put(key, toJsonObject(value as Map<String, Any>))
                }
                is List<*> -> obj.put(key, JSONArray(value.map { it.toString() }))
                else -> obj.put(key, value.toString())
            }
        }
        return obj
    }

    // =========================================================================
    // Poseidon2 commitment helpers
    // =========================================================================

    fun computePrivateNullifier(dg1: ByteArray, econtent: ByteArray, sodSignature: ByteArray): String {
        val fields = mutableListOf<BigInteger>()
        fields.addAll(Poseidon2.packBytesIntoFields(dg1))
        fields.addAll(Poseidon2.packBytesIntoFields(econtent))
        fields.addAll(Poseidon2.packBytesIntoFields(sodSignature))
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    fun computeSodHashRaw(econtent: ByteArray): BigInteger {
        return Poseidon2.hash(Poseidon2.packBytesIntoFields(econtent))
    }

    fun computeSodHash(econtent: ByteArray): String {
        return Poseidon2.fieldToHex(computeSodHashRaw(econtent))
    }

    fun computeCscKeyNeHash(cscaPubkey: ByteArray, cscaExponent: Long): String {
        val domain = Poseidon2.hexToField(RSA_KEY_NE_HASH_DOMAIN)
        val packedPubkey = Poseidon2.packBytesIntoFields(cscaPubkey)
        val exponentBytes = ByteArray(4)
        exponentBytes[0] = ((cscaExponent shr 24) and 0xFF).toByte()
        exponentBytes[1] = ((cscaExponent shr 16) and 0xFF).toByte()
        exponentBytes[2] = ((cscaExponent shr 8) and 0xFF).toByte()
        exponentBytes[3] = (cscaExponent and 0xFF).toByte()
        val packedExponent = Poseidon2.packBytesIntoFields(exponentBytes, 31)

        val hashInput = mutableListOf(domain)
        hashInput.addAll(packedPubkey)
        hashInput.addAll(packedExponent)
        return Poseidon2.fieldToHex(Poseidon2.hash(hashInput))
    }

    fun computeTestMerkleRoot(leaf: String): String {
        var current = Poseidon2.hexToField(leaf)
        for (i in 0 until TREE_DEPTH) {
            current = Poseidon2.hash(listOf(current, BigInteger.ZERO))
        }
        return Poseidon2.fieldToHex(current)
    }
}
