import Foundation
import BigInt
import Verity

public struct PipelineResult {
    public let proofStage1: Data
    public let proofStage2: Data
    public let proofStage3: Data
    public let proofStage4: Data
    public let leaf: String
    public let scopedNullifier: String
}

public enum Pipeline {

    public static func run(
        pkpDir: String,
        data: PassportData,
        config: WitnessConfig
    ) throws -> PipelineResult {
        let pipelineStart = CFAbsoluteTimeGetCurrent()

        let tbsCert = padToSize(data.tbsCertificate720, targetSize: Constants.maxTbsSize1300)

        // Compute all commitment values natively
        var t = CFAbsoluteTimeGetCurrent()
        let cscKeyNeHash = WitnessBuilder.computeCscKeyNeHash(cscaPubkey: data.cscaModulus, cscaExponent: data.cscaExponent)
        let commOut1 = CommitmentComputer.computeStage1CommOut(salt: "0x1", country: data.country, tbsCertificate: tbsCert)
        let privateNullifier = WitnessBuilder.computePrivateNullifier(
            dg1: data.dg1Padded, econtent: data.econtent, sodSignature: data.sodSignature
        )
        let commOut2 = CommitmentComputer.computeStage2CommOut(
            saltOut: "0x2", country: data.country, signedAttributes: data.signedAttrs,
            signedAttributesSize: data.signedAttributesSize,
            dg1: data.dg1Padded, econtent: data.econtent, privateNullifier: privateNullifier
        )
        let leaf = CommitmentComputer.computeLeaf(rDg1: config.rDg1, dg1: data.dg1Padded, econtent: data.econtent)
        let sodHash = WitnessBuilder.computeSodHash(econtent: data.econtent)
        let testMerkleRoot = WitnessBuilder.computeTestMerkleRoot(leaf: leaf)
        print(String(format: "Commitments computed in %.2fs", elapsed(t)))

        let verity = try Verity(backend: .provekit)

        // Build witnesses for all stages
        let stage1Witness: [String: Any] = [
            "csc_key_ne_hash": cscKeyNeHash,
            "csc_pubkey": data.cscaModulus.toIntList(),
            "csc_pubkey_redc_param": data.cscaBarrett.toIntList(),
            "salt": "0x1",
            "country": data.country,
            "tbs_certificate": tbsCert.toIntList(),
            "dsc_signature": data.cscaSignature.toIntList(),
            "tbs_certificate_len": Int64(data.tbsCertificateLen),
            "exponent": data.cscaExponent,
        ]
        let stage2Witness: [String: Any] = [
            "comm_in": commOut1,
            "salt_in": "0x1",
            "salt_out": "0x2",
            "dg1": data.dg1Padded.toIntList(),
            "dsc_pubkey": data.dscModulus.toIntList(),
            "dsc_pubkey_redc_param": data.dscBarrett.toIntList(),
            "dsc_pubkey_offset_in_dsc_cert": Int64(data.dscPubkeyOffset),
            "exponent": data.dscExponent,
            "exponent_offset_in_dsc_cert": Int64(data.dscExponentOffset),
            "sod_signature": data.sodSignature.toIntList(),
            "tbs_certificate": tbsCert.toIntList(),
            "signed_attributes": data.signedAttrs.toIntList(),
            "e_content": data.econtent.toIntList(),
        ]
        let stage3Witness: [String: Any] = [
            "comm_in": commOut2,
            "salt_in": "0x2",
            "dg1": data.dg1Padded.toIntList(),
            "dg1_padded_length": Int64(data.dg1Len),
            "dg1_hash_offset": Int64(data.dg1HashOffset),
            "signed_attributes": data.signedAttrs.toIntList(),
            "signed_attributes_size": Int64(data.signedAttributesSize),
            "e_content": data.econtent.toIntList(),
            "e_content_len": Int64(data.econtentLen),
            "private_nullifier": privateNullifier,
            "r_dg1": config.rDg1,
        ]
        let stage4Witness: [String: Any] = [
            "root": testMerkleRoot,
            "sod_hash": sodHash,
            "dg1": data.dg1Padded.toIntList(),
            "r_dg1": config.rDg1,
            "service_scope": config.serviceScope,
            "service_subscope": config.serviceSubscope,
            "current_date": config.currentDate,
            "leaf_index": config.leafIndex,
            "merkle_path": config.merklePath,
            "min_age_required": config.minAgeRequired,
            "max_age_required": config.maxAgeRequired,
            "nullifier_secret": config.nullifierSecret,
        ]

        let stages: [(name: String, witness: [String: Any], label: String)] = [
            ("t_add_dsc_1300", stage1Witness, "comm_out=\(String(commOut1.prefix(18)))"),
            ("t_add_id_data_1300", stage2Witness, "comm_out=\(String(commOut2.prefix(18)))"),
            ("t_add_integrity_commit", stage3Witness, "leaf=\(String(leaf.prefix(18)))"),
            ("t_attest", stage4Witness, "nullifier="),
        ]

        var proofs: [Data] = []

        for (i, (name, witness, label)) in stages.enumerated() {
            let witnessJson = WitnessBuilder.toJson(witness)
            t = CFAbsoluteTimeGetCurrent()
            let prover = try loadProver(verity: verity, pkpDir: pkpDir, name: name)
            let loadTime = elapsed(t)
            t = CFAbsoluteTimeGetCurrent()
            let proof = try prover.prove(witness: Witness(json: witnessJson))
            prover.close()
            proofs.append(proof.data)
            print(String(format: "[%d/4] %-22@ done in %.2fs (load %.2fs)  %@",
                          i + 1, name as NSString, elapsed(t), loadTime, label as NSString))
        }

        let scopedNullifier = CommitmentComputer.computeScopedNullifier(
            dg1: data.dg1Padded, econtent: data.econtent,
            serviceScope: config.serviceScope, serviceSubscope: config.serviceSubscope,
            nullifierSecret: config.nullifierSecret
        )

        let totalTime = elapsed(pipelineStart)
        print(String(format: "\nPipeline complete in %.2fs", totalTime))
        print("  leaf:              \(leaf)")
        print("  scoped_nullifier:  \(scopedNullifier)")

        return PipelineResult(
            proofStage1: proofs[0],
            proofStage2: proofs[1],
            proofStage3: proofs[2],
            proofStage4: proofs[3],
            leaf: leaf,
            scopedNullifier: scopedNullifier
        )
    }

    private static func elapsed(_ start: CFAbsoluteTime) -> Double {
        CFAbsoluteTimeGetCurrent() - start
    }

    private static func loadProver(verity: Verity, pkpDir: String, name: String) throws -> ProverScheme {
        let path = (pkpDir as NSString).appendingPathComponent("\(name)-prover.pkp")
        guard FileManager.default.fileExists(atPath: path) else {
            throw PassportError.dataNotFound("Prover file not found: \(path)")
        }
        return try verity.loadProver(from: path)
    }
}
