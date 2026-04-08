package verity.passport.prover

import org.json.JSONArray
import org.json.JSONObject
import verity.passport.prover.Constants.RSA_KEY_NE_HASH_DOMAIN
import verity.passport.prover.Constants.TREE_DEPTH
import verity.passport.prover.Constants.ZERO_FIELD
import java.math.BigInteger

/**
 * Configuration for witness construction and proof generation.
 * Default values provide reasonable testing defaults for all optional parameters.
 */
public data class WitnessConfig(
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

/**
 * Builds and serializes witness inputs for the passport-prover circuits.
 *
 * All Poseidon2-based commitment helpers delegate to [Poseidon2] and must
 * not be modified without a corresponding update to the circuit constants.
 */
public object WitnessBuilder {

    // =========================================================================
    // Serialization
    // =========================================================================

    /**
     * Serializes a witness map to a pretty-printed JSON string suitable for
     * passing to [xyz.atheon.verity.Witness.fromJson].
     *
     * Nested [Map] values are recursively serialized; [List] values have each
     * element converted via [toString]; all other values use [toString].
     */
    public fun toJson(witness: Map<String, Any>): String {
        return toJsonObject(witness).toString(2)
    }

    @Suppress("UNCHECKED_CAST") // Map<*, *> casts are guarded by the key type check in toJson callers
    private fun toJsonObject(map: Map<String, Any>): JSONObject {
        val obj = JSONObject()
        for ((key, value) in map) {
            when (value) {
                is Map<*, *> -> obj.put(key, toJsonObject(value as Map<String, Any>))
                is List<*> -> obj.put(key, JSONArray(value.map { it.toString() }))
                else -> obj.put(key, value.toString())
            }
        }
        return obj
    }

    // =========================================================================
    // Poseidon2 commitment helpers
    // =========================================================================

    /**
     * Computes the private nullifier by hashing the packed byte representations
     * of [dg1], [econtent], and [sodSignature] together via Poseidon2.
     */
    public fun computePrivateNullifier(dg1: ByteArray, econtent: ByteArray, sodSignature: ByteArray): String {
        val fields = buildList {
            addAll(Poseidon2.packBytesIntoFields(dg1))
            addAll(Poseidon2.packBytesIntoFields(econtent))
            addAll(Poseidon2.packBytesIntoFields(sodSignature))
        }
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    /**
     * Returns the raw Poseidon2 hash of the packed [econtent] bytes as a [BigInteger].
     */
    public fun computeSodHashRaw(econtent: ByteArray): BigInteger {
        return Poseidon2.hash(Poseidon2.packBytesIntoFields(econtent))
    }

    /**
     * Returns the hex-encoded Poseidon2 hash of the packed [econtent] bytes.
     */
    public fun computeSodHash(econtent: ByteArray): String {
        return Poseidon2.fieldToHex(computeSodHashRaw(econtent))
    }

    /**
     * Computes a domain-separated hash of the CSCA RSA public key modulus and exponent.
     *
     * The domain prefix [RSA_KEY_NE_HASH_DOMAIN] prevents cross-context collisions.
     * The [cscaExponent] is encoded as a big-endian 4-byte value before packing.
     */
    public fun computeCscKeyNeHash(cscaPubkey: ByteArray, cscaExponent: Long): String {
        val domain = Poseidon2.hexToField(RSA_KEY_NE_HASH_DOMAIN)
        val exponentBytes = ByteArray(4).also {
            it[0] = ((cscaExponent shr 24) and 0xFF).toByte()
            it[1] = ((cscaExponent shr 16) and 0xFF).toByte()
            it[2] = ((cscaExponent shr 8) and 0xFF).toByte()
            it[3] = (cscaExponent and 0xFF).toByte()
        }
        val fields = buildList {
            add(domain)
            addAll(Poseidon2.packBytesIntoFields(cscaPubkey))
            addAll(Poseidon2.packBytesIntoFields(exponentBytes, 31))
        }
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    /**
     * Computes a test Merkle root by hashing [leaf] with [TREE_DEPTH] zero siblings,
     * producing a deterministic root for a single-leaf tree used in testing.
     */
    public fun computeTestMerkleRoot(leaf: String): String {
        var current = Poseidon2.hexToField(leaf)
        for (i in 0 until TREE_DEPTH) {
            current = Poseidon2.hash(listOf(current, BigInteger.ZERO))
        }
        return Poseidon2.fieldToHex(current)
    }
}
