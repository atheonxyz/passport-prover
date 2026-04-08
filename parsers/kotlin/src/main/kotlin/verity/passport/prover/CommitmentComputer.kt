package verity.passport.prover

import java.math.BigInteger

/**
 * Computes Poseidon2 commitment values natively, matching the Noir circuits.
 * These are used to chain stages together (comm_out from stage N = comm_in for stage N+1).
 */
public object CommitmentComputer {

    /**
     * Stage 1 commitment: hash_salt_country_tbs(salt, country, tbs_certificate)
     *
     * hash_input = [salt, packed_country, packed_tbs...]
     * - country: 3 bytes → 1 field
     * - tbs: 1400 bytes → ceil(1400/31) = 46 fields
     * Total: 1 + 1 + 46 = 48 fields
     *
     * @param salt Hex-encoded salt field element.
     * @param country ISO 3166-1 alpha-3 country code (3 ASCII bytes).
     * @param tbsCertificate Raw DER-encoded TBSCertificate bytes.
     * @return Hex-encoded Poseidon2 commitment field element.
     */
    public fun computeStage1CommOut(
        salt: String,
        country: String,
        tbsCertificate: ByteArray,
    ): String {
        val fields = buildList {
            add(Poseidon2.hexToField(salt))
            addAll(Poseidon2.packBytesIntoFields(country.toByteArray(Charsets.US_ASCII)))
            addAll(Poseidon2.packBytesIntoFields(tbsCertificate))
        }
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    /**
     * Stage 2 commitment: hash_salt_country_signed_attr_dg1_e_content_private_nullifier(
     *     salt_out, country, signed_attributes, signed_attr_size, dg1, e_content, private_nullifier
     * )
     *
     * hash_input = [salt_out, packed_country, packed_signed_attrs..., signed_attr_size, packed_dg1..., packed_e_content..., private_nullifier]
     *
     * @param saltOut Hex-encoded salt output from stage 1.
     * @param country ISO 3166-1 alpha-3 country code (3 ASCII bytes).
     * @param signedAttributes Raw signed attributes bytes from the SOD.
     * @param signedAttributesSize Actual byte length of [signedAttributes] used by the circuit.
     * @param dg1 Raw DG1 data group bytes.
     * @param econtent Raw eContent bytes from the SOD.
     * @param privateNullifier Hex-encoded private nullifier field element.
     * @return Hex-encoded Poseidon2 commitment field element.
     */
    public fun computeStage2CommOut(
        saltOut: String,
        country: String,
        signedAttributes: ByteArray,
        signedAttributesSize: Int,
        dg1: ByteArray,
        econtent: ByteArray,
        privateNullifier: String,
    ): String {
        val fields = buildList {
            add(Poseidon2.hexToField(saltOut))
            addAll(Poseidon2.packBytesIntoFields(country.toByteArray(Charsets.US_ASCII)))
            addAll(Poseidon2.packBytesIntoFields(signedAttributes))
            add(BigInteger.valueOf(signedAttributesSize.toLong()))
            addAll(Poseidon2.packBytesIntoFields(dg1))
            addAll(Poseidon2.packBytesIntoFields(econtent))
            add(Poseidon2.hexToField(privateNullifier))
        }
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    /**
     * Computes h_dg1 = Poseidon2([r_dg1, packed_dg1...])
     *
     * - dg1: 95 bytes → ceil(95/31) = 4 fields
     * Total: 1 + 4 = 5 fields
     *
     * @param rDg1 Hex-encoded randomness field element for DG1 commitment.
     * @param dg1 Raw DG1 data group bytes.
     * @return Poseidon2 hash of the DG1 commitment as a [BigInteger] field element.
     */
    public fun computeHDg1(rDg1: String, dg1: ByteArray): BigInteger {
        val fields = buildList {
            add(Poseidon2.hexToField(rDg1))
            addAll(Poseidon2.packBytesIntoFields(dg1))
        }
        return Poseidon2.hash(fields)
    }

    /**
     * Stage 3 leaf: Poseidon2([h_dg1, sod_hash])
     *
     * Computes the Merkle tree leaf for the passport by hashing the DG1 commitment
     * together with the SOD hash derived from [econtent].
     *
     * @param rDg1 Hex-encoded randomness field element for DG1 commitment.
     * @param dg1 Raw DG1 data group bytes.
     * @param econtent Raw eContent bytes used to derive the SOD hash.
     * @return Hex-encoded Poseidon2 leaf field element.
     */
    public fun computeLeaf(rDg1: String, dg1: ByteArray, econtent: ByteArray): String {
        val hDg1 = computeHDg1(rDg1, dg1)
        val sodHash = WitnessBuilder.computeSodHashRaw(econtent)
        return Poseidon2.fieldToHex(Poseidon2.hash(listOf(hDg1, sodHash)))
    }

    /**
     * Stage 4 scoped nullifier:
     *   private_nullifier = Poseidon2([packed_dg1..., sod_hash])
     *   scoped_nullifier = Poseidon2([private_nullifier, service_scope, service_subscope]) (if no secret)
     *                    = Poseidon2([private_nullifier, service_scope, service_subscope, secret]) (if secret)
     *
     * @param dg1 Raw DG1 data group bytes.
     * @param econtent Raw eContent bytes used to derive the SOD hash.
     * @param serviceScope Hex-encoded service scope field element.
     * @param serviceSubscope Hex-encoded service subscope field element.
     * @param nullifierSecret Hex-encoded nullifier secret; use [Constants.ZERO_FIELD] to omit.
     * @return Hex-encoded scoped nullifier field element.
     */
    public fun computeScopedNullifier(
        dg1: ByteArray,
        econtent: ByteArray,
        serviceScope: String,
        serviceSubscope: String,
        nullifierSecret: String,
    ): String {
        val sodHash = WitnessBuilder.computeSodHashRaw(econtent)

        // private_nullifier for t_attest = Poseidon2(packed_dg1 ++ [sod_hash])
        val nullFields = buildList {
            addAll(Poseidon2.packBytesIntoFields(dg1))
            add(sodHash)
        }
        val privateNullifier = Poseidon2.hash(nullFields)

        val scopeFields = buildList {
            add(privateNullifier)
            add(Poseidon2.hexToField(serviceScope))
            add(Poseidon2.hexToField(serviceSubscope))
            if (nullifierSecret != Constants.ZERO_FIELD) {
                add(Poseidon2.hexToField(nullifierSecret))
            }
        }
        return Poseidon2.fieldToHex(Poseidon2.hash(scopeFields))
    }
}
