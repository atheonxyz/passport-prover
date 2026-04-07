package verity.passport.prover

import verity.passport.prover.Constants.MAX_TBS_SIZE_1300
import xyz.atheon.verity.Backend
import xyz.atheon.verity.Proof
import xyz.atheon.verity.ProverScheme
import xyz.atheon.verity.Verity
import xyz.atheon.verity.Witness
import java.io.File

data class PipelineResult(
    val proofStage1: Proof,
    val proofStage2: Proof,
    val proofStage3: Proof,
    val proofStage4: Proof,
    val leaf: String,
    val scopedNullifier: String,
)

object Pipeline {

    fun run(
        pkpDir: String,
        data: PassportData,
        config: WitnessConfig,
    ): PipelineResult {
        val pipelineStart = System.nanoTime()
        val verity = Verity(Backend.PROVEKIT)

        val tbsCert = PassportReader.fitBytes(data.tbsCertificate720, MAX_TBS_SIZE_1300, "TBS certificate")

        // Compute all commitment values natively (Verity SDK doesn't expose public outputs)
        var t = System.nanoTime()
        val cscKeyNeHash = WitnessBuilder.computeCscKeyNeHash(data.cscaModulus, data.cscaExponent)
        val commOut1 = CommitmentComputer.computeStage1CommOut("0x1", data.country, tbsCert)
        val privateNullifier = WitnessBuilder.computePrivateNullifier(
            data.dg1Padded, data.econtent, data.sodSignature
        )
        val commOut2 = CommitmentComputer.computeStage2CommOut(
            "0x2", data.country, data.signedAttrs, data.signedAttributesSize,
            data.dg1Padded, data.econtent, privateNullifier
        )
        val leaf = CommitmentComputer.computeLeaf(config.rDg1, data.dg1Padded, data.econtent)
        val sodHash = WitnessBuilder.computeSodHash(data.econtent)
        val testMerkleRoot = WitnessBuilder.computeTestMerkleRoot(leaf)
        System.err.println("Commitments computed in %.2fs".format(elapsed(t)))

        // -- Stage 1: t_add_dsc_1300 --
        t = System.nanoTime()
        val prover1 = loadProver(verity, pkpDir, "t_add_dsc_1300")
        val loadTime1 = elapsed(t)
        val stage1Witness = mapOf(
            "csc_key_ne_hash" to cscKeyNeHash,
            "csc_pubkey" to data.cscaModulus.toIntList(),
            "csc_pubkey_redc_param" to data.cscaBarrett.toIntList(),
            "salt" to "0x1",
            "country" to data.country,
            "tbs_certificate" to tbsCert.toIntList(),
            "dsc_signature" to data.cscaSignature.toIntList(),
            "tbs_certificate_len" to data.tbsCertificateLen.toLong(),
            "exponent" to data.cscaExponent,
        )
        t = System.nanoTime()
        val proof1 = prover1.prove(Witness.fromJson(WitnessBuilder.toJson(stage1Witness)))
        prover1.close()
        System.err.println("[1/4] t_add_dsc_1300      done in %.2fs (load %.2fs)  comm_out=%s".format(
            elapsed(t), loadTime1, commOut1.take(18)))

        // -- Stage 2: t_add_id_data_1300 --
        t = System.nanoTime()
        val prover2 = loadProver(verity, pkpDir, "t_add_id_data_1300")
        val loadTime2 = elapsed(t)
        val stage2Witness = mapOf(
            "comm_in" to commOut1,
            "salt_in" to "0x1",
            "salt_out" to "0x2",
            "dg1" to data.dg1Padded.toIntList(),
            "dsc_pubkey" to data.dscModulus.toIntList(),
            "dsc_pubkey_redc_param" to data.dscBarrett.toIntList(),
            "dsc_pubkey_offset_in_dsc_cert" to data.dscPubkeyOffset.toLong(),
            "exponent" to data.dscExponent,
            "exponent_offset_in_dsc_cert" to data.dscExponentOffset.toLong(),
            "sod_signature" to data.sodSignature.toIntList(),
            "tbs_certificate" to tbsCert.toIntList(),
            "signed_attributes" to data.signedAttrs.toIntList(),
            "e_content" to data.econtent.toIntList(),
        )
        t = System.nanoTime()
        val proof2 = prover2.prove(Witness.fromJson(WitnessBuilder.toJson(stage2Witness)))
        prover2.close()
        System.err.println("[2/4] t_add_id_data_1300  done in %.2fs (load %.2fs)  comm_out=%s".format(
            elapsed(t), loadTime2, commOut2.take(18)))

        // -- Stage 3: t_add_integrity_commit --
        t = System.nanoTime()
        val prover3 = loadProver(verity, pkpDir, "t_add_integrity_commit")
        val loadTime3 = elapsed(t)
        val stage3Witness = mapOf(
            "comm_in" to commOut2,
            "salt_in" to "0x2",
            "dg1" to data.dg1Padded.toIntList(),
            "dg1_padded_length" to data.dg1Len.toLong(),
            "dg1_hash_offset" to data.dg1HashOffset.toLong(),
            "signed_attributes" to data.signedAttrs.toIntList(),
            "signed_attributes_size" to data.signedAttributesSize.toLong(),
            "e_content" to data.econtent.toIntList(),
            "e_content_len" to data.econtentLen.toLong(),
            "private_nullifier" to privateNullifier,
            "r_dg1" to config.rDg1,
        )
        t = System.nanoTime()
        val proof3 = prover3.prove(Witness.fromJson(WitnessBuilder.toJson(stage3Witness)))
        prover3.close()
        System.err.println("[3/4] t_add_integrity     done in %.2fs (load %.2fs)  leaf=%s".format(
            elapsed(t), loadTime3, leaf.take(18)))

        // -- Stage 4: t_attest --
        t = System.nanoTime()
        val prover4 = loadProver(verity, pkpDir, "t_attest")
        val loadTime4 = elapsed(t)
        val stage4Witness = mapOf(
            "root" to testMerkleRoot,
            "sod_hash" to sodHash,
            "dg1" to data.dg1Padded.toIntList(),
            "r_dg1" to config.rDg1,
            "service_scope" to config.serviceScope,
            "service_subscope" to config.serviceSubscope,
            "current_date" to config.currentDate,
            "leaf_index" to config.leafIndex,
            "merkle_path" to config.merklePath,
            "min_age_required" to config.minAgeRequired,
            "max_age_required" to config.maxAgeRequired,
            "nullifier_secret" to config.nullifierSecret,
        )
        t = System.nanoTime()
        val proof4 = prover4.prove(Witness.fromJson(WitnessBuilder.toJson(stage4Witness)))
        prover4.close()

        val scopedNullifier = CommitmentComputer.computeScopedNullifier(
            data.dg1Padded, data.econtent,
            config.serviceScope, config.serviceSubscope, config.nullifierSecret
        )
        System.err.println("[4/4] t_attest            done in %.2fs (load %.2fs)  nullifier=%s".format(
            elapsed(t), loadTime4, scopedNullifier.take(18)))

        val totalTime = elapsed(pipelineStart)
        System.err.println()
        System.err.println("Pipeline complete in %.2fs".format(totalTime))
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

    private fun elapsed(startNanos: Long): Double =
        (System.nanoTime() - startNanos) / 1_000_000_000.0

    private fun loadProver(verity: Verity, pkpDir: String, name: String): ProverScheme {
        val path = File(pkpDir, "$name-prover.pkp").absolutePath
        if (!File(path).exists()) {
            throw IllegalArgumentException("Prover file not found: $path")
        }
        return verity.loadProver(path)
    }

    private fun ByteArray.toIntList(): List<Int> = map { it.toInt() and 0xFF }

}
