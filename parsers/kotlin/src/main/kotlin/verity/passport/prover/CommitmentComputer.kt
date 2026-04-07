package verity.passport.prover

import java.math.BigInteger

/**
 * Computes Poseidon2 commitment values natively, matching the Noir circuits.
 * These are used to chain stages together (comm_out from stage N = comm_in for stage N+1).
 */
object CommitmentComputer {

    /**
     * Stage 1 commitment: hash_salt_country_tbs(salt, country, tbs_certificate)
     *
     * hash_input = [salt, packed_country, packed_tbs...]
     * - country: 3 bytes → 1 field
     * - tbs: 1400 bytes → ceil(1400/31) = 46 fields
     * Total: 1 + 1 + 46 = 48 fields
     */
    fun computeStage1CommOut(
        salt: String,
        country: String,
        tbsCertificate: ByteArray,
    ): String {
        val fields = mutableListOf<BigInteger>()
        fields.add(Poseidon2.hexToField(salt))
        fields.addAll(Poseidon2.packBytesIntoFields(country.toByteArray(Charsets.US_ASCII)))
        fields.addAll(Poseidon2.packBytesIntoFields(tbsCertificate))
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    /**
     * Stage 2 commitment: hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
     *     salt_out, country, signed_attributes, signed_attr_size, dg1, e_content, private_nullifier
     * )
     *
     * hash_input = [salt_out, packed_country, packed_signed_attrs..., signed_attr_size, packed_dg1..., packed_e_content..., private_nullifier]
     */
    fun computeStage2CommOut(
        saltOut: String,
        country: String,
        signedAttributes: ByteArray,
        signedAttributesSize: Int,
        dg1: ByteArray,
        econtent: ByteArray,
        privateNullifier: String,
    ): String {
        val fields = mutableListOf<BigInteger>()
        fields.add(Poseidon2.hexToField(saltOut))
        fields.addAll(Poseidon2.packBytesIntoFields(country.toByteArray(Charsets.US_ASCII)))
        fields.addAll(Poseidon2.packBytesIntoFields(signedAttributes))
        fields.add(BigInteger.valueOf(signedAttributesSize.toLong()))
        fields.addAll(Poseidon2.packBytesIntoFields(dg1))
        fields.addAll(Poseidon2.packBytesIntoFields(econtent))
        fields.add(Poseidon2.hexToField(privateNullifier))
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    /**
     * Compute h_dg1 = Poseidon2([r_dg1, packed_dg1...])
     * - dg1: 95 bytes → ceil(95/31) = 4 fields
     * Total: 1 + 4 = 5 fields
     */
    fun computeHDg1(rDg1: String, dg1: ByteArray): BigInteger {
        val fields = mutableListOf<BigInteger>()
        fields.add(Poseidon2.hexToField(rDg1))
        fields.addAll(Poseidon2.packBytesIntoFields(dg1))
        return Poseidon2.hash(fields)
    }

    /**
     * Stage 3 leaf: Poseidon2([h_dg1, sod_hash])
     */
    fun computeLeaf(rDg1: String, dg1: ByteArray, econtent: ByteArray): String {
        val hDg1 = computeHDg1(rDg1, dg1)
        val sodHash = Poseidon2.hash(Poseidon2.packBytesIntoFields(econtent))
        return Poseidon2.fieldToHex(Poseidon2.hash(listOf(hDg1, sodHash)))
    }

    /**
     * Stage 4 scoped_nullifier:
     *   private_nullifier = Poseidon2([packed_dg1..., sod_hash])
     *   scoped_nullifier = Poseidon2([private_nullifier, service_scope, service_subscope]) (if no secret)
     *                    = Poseidon2([private_nullifier, service_scope, service_subscope, secret]) (if secret)
     */
    fun computeScopedNullifier(
        dg1: ByteArray,
        econtent: ByteArray,
        serviceScope: String,
        serviceSubscope: String,
        nullifierSecret: String,
    ): String {
        val sodHash = Poseidon2.hash(Poseidon2.packBytesIntoFields(econtent))

        // private_nullifier for t_attest = Poseidon2(packed_dg1 ++ [sod_hash])
        val nullFields = mutableListOf<BigInteger>()
        nullFields.addAll(Poseidon2.packBytesIntoFields(dg1))
        nullFields.add(sodHash)
        val privateNullifier = Poseidon2.hash(nullFields)

        val scopeFields = mutableListOf(
            privateNullifier,
            Poseidon2.hexToField(serviceScope),
            Poseidon2.hexToField(serviceSubscope),
        )
        if (nullifierSecret != Constants.ZERO_FIELD) {
            scopeFields.add(Poseidon2.hexToField(nullifierSecret))
        }
        return Poseidon2.fieldToHex(Poseidon2.hash(scopeFields))
    }
}
