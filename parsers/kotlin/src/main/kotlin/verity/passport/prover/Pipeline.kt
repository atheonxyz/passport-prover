package verity.passport.prover

import verity.passport.prover.Constants.MAX_TBS_SIZE_1300
import xyz.atheon.verity.Backend
import xyz.atheon.verity.Proof
import xyz.atheon.verity.ProverScheme
import xyz.atheon.verity.Verity
import xyz.atheon.verity.Witness
import java.io.File
import kotlin.time.TimeSource
import kotlin.time.measureTimedValue

/**
 * The result of a complete proving pipeline run, containing all four stage proofs
 * along with the Merkle tree leaf and scoped nullifier values.
 */
public data class PipelineResult(
    val proofStage1: Proof,
    val proofStage2: Proof,
    val proofStage3: Proof,
    val proofStage4: Proof,
    val leaf: String,
    val scopedNullifier: String,
)

public object Pipeline {

    /**
     * Runs the complete 4-stage proving pipeline.
     *
     * 1. **t_add_dsc_1300** — Verifies the DSC certificate against CSCA
     * 2. **t_add_id_data_1300** — Verifies passport data against DSC
     * 3. **t_add_integrity_commit** — Computes integrity commitments and leaf
     * 4. **t_attest** — Generates attestation with Merkle proof and nullifier
     */
    public fun run(
        pkpDir: String,
        data: PassportData,
        config: WitnessConfig,
    ): PipelineResult {
        val clock = TimeSource.Monotonic
        val pipelineStart = clock.markNow()
        val verity = Verity(Backend.PROVEKIT)

        val tbsCert = PassportReader.fitBytes(data.tbsCertificate720, MAX_TBS_SIZE_1300, "TBS certificate")

        // Compute all commitment values natively (Verity SDK doesn't expose public outputs)
        val commitStart = clock.markNow()
        val cscKeyNeHash = WitnessBuilder.computeCscKeyNeHash(data.cscaModulus, data.cscaExponent)
        val commOut1 = CommitmentComputer.computeStage1CommOut("0x1", data.country, tbsCert)
        val privateNullifier = WitnessBuilder.computePrivateNullifier(
            data.dg1Padded, data.econtent, data.sodSignature,
        )
        val commOut2 = CommitmentComputer.computeStage2CommOut(
            "0x2", data.country, data.signedAttrs, data.signedAttributesSize,
            data.dg1Padded, data.econtent, privateNullifier,
        )
        val leaf = CommitmentComputer.computeLeaf(config.rDg1, data.dg1Padded, data.econtent)
        val sodHash = WitnessBuilder.computeSodHash(data.econtent)
        val testMerkleRoot = WitnessBuilder.computeTestMerkleRoot(leaf)
        System.err.println("Commitments computed in ${commitStart.elapsedNow()}")

        // -- Stage 1: t_add_dsc_1300 --
        val proof1 = proveStage(verity, pkpDir, "t_add_dsc_1300", "1/4", mapOf(
            "csc_key_ne_hash" to cscKeyNeHash,
            "csc_pubkey" to data.cscaModulus.toUnsignedIntList(),
            "csc_pubkey_redc_param" to data.cscaBarrett.toUnsignedIntList(),
            "salt" to "0x1",
            "country" to data.country,
            "tbs_certificate" to tbsCert.toUnsignedIntList(),
            "dsc_signature" to data.cscaSignature.toUnsignedIntList(),
            "tbs_certificate_len" to data.tbsCertificateLen.toLong(),
            "exponent" to data.cscaExponent,
        )) { "comm_out=${commOut1.take(18)}" }

        // -- Stage 2: t_add_id_data_1300 --
        val proof2 = proveStage(verity, pkpDir, "t_add_id_data_1300", "2/4", mapOf(
            "comm_in" to commOut1,
            "salt_in" to "0x1",
            "salt_out" to "0x2",
            "dg1" to data.dg1Padded.toUnsignedIntList(),
            "dsc_pubkey" to data.dscModulus.toUnsignedIntList(),
            "dsc_pubkey_redc_param" to data.dscBarrett.toUnsignedIntList(),
            "dsc_pubkey_offset_in_dsc_cert" to data.dscPubkeyOffset.toLong(),
            "exponent" to data.dscExponent,
            "exponent_offset_in_dsc_cert" to data.dscExponentOffset.toLong(),
            "sod_signature" to data.sodSignature.toUnsignedIntList(),
            "tbs_certificate" to tbsCert.toUnsignedIntList(),
            "signed_attributes" to data.signedAttrs.toUnsignedIntList(),
            "e_content" to data.econtent.toUnsignedIntList(),
        )) { "comm_out=${commOut2.take(18)}" }

        // -- Stage 3: t_add_integrity_commit --
        val proof3 = proveStage(verity, pkpDir, "t_add_integrity_commit", "3/4", mapOf(
            "comm_in" to commOut2,
            "salt_in" to "0x2",
            "dg1" to data.dg1Padded.toUnsignedIntList(),
            "dg1_padded_length" to data.dg1Len.toLong(),
            "dg1_hash_offset" to data.dg1HashOffset.toLong(),
            "signed_attributes" to data.signedAttrs.toUnsignedIntList(),
            "signed_attributes_size" to data.signedAttributesSize.toLong(),
            "e_content" to data.econtent.toUnsignedIntList(),
            "e_content_len" to data.econtentLen.toLong(),
            "private_nullifier" to privateNullifier,
            "r_dg1" to config.rDg1,
        )) { "leaf=${leaf.take(18)}" }

        // -- Stage 4: t_attest --
        val proof4 = proveStage(verity, pkpDir, "t_attest", "4/4", mapOf(
            "root" to testMerkleRoot,
            "sod_hash" to sodHash,
            "dg1" to data.dg1Padded.toUnsignedIntList(),
            "r_dg1" to config.rDg1,
            "service_scope" to config.serviceScope,
            "service_subscope" to config.serviceSubscope,
            "current_date" to config.currentDate,
            "leaf_index" to config.leafIndex,
            "merkle_path" to config.merklePath,
            "min_age_required" to config.minAgeRequired,
            "max_age_required" to config.maxAgeRequired,
            "nullifier_secret" to config.nullifierSecret,
        )) { "nullifier placeholder" }

        val scopedNullifier = CommitmentComputer.computeScopedNullifier(
            data.dg1Padded, data.econtent,
            config.serviceScope, config.serviceSubscope, config.nullifierSecret,
        )

        System.err.println()
        System.err.println("Pipeline complete in ${pipelineStart.elapsedNow()}")
        System.err.println("  leaf:              $leaf")
        System.err.println("  scoped_nullifier:  $scopedNullifier")

        return PipelineResult(
            proofStage1 = proof1,
            proofStage2 = proof2,
            proofStage3 = proof3,
            proofStage4 = proof4,
            leaf = leaf,
            scopedNullifier = scopedNullifier,
        )
    }

    /**
     * Loads a prover, generates a proof, and closes the prover.
     * Logs stage timing and an optional summary string.
     *
     * [ProverScheme] implements [AutoCloseable], so [use] guarantees cleanup
     * even when [ProverScheme.prove] throws.
     */
    private fun proveStage(
        verity: Verity,
        pkpDir: String,
        circuitName: String,
        stageLabel: String,
        witness: Map<String, Any>,
        summary: () -> String = { "" },
    ): Proof {
        val clock = TimeSource.Monotonic

        val (prover, loadDuration) = measureTimedValue {
            loadProver(verity, pkpDir, circuitName)
        }

        val (proof, proveDuration) = measureTimedValue {
            prover.use { it.prove(Witness.fromJson(WitnessBuilder.toJson(witness))) }
        }

        val label = circuitName.padEnd(24)
        System.err.println("[$stageLabel] $label done in $proveDuration (load $loadDuration)  ${summary()}")

        return proof
    }

    private fun loadProver(verity: Verity, pkpDir: String, name: String): ProverScheme {
        val path = File(pkpDir, "$name-prover.pkp").absolutePath
        require(File(path).exists()) { "Prover file not found: $path" }
        return verity.loadProver(path)
    }

    private fun ByteArray.toUnsignedIntList(): List<Int> = map { it.toInt() and 0xFF }
}
