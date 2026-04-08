import Foundation
import BigInt
import Verity

// MARK: - Pipeline Result

public struct PipelineResult: Sendable {
    public let proofStage1: Data
    public let proofStage2: Data
    public let proofStage3: Data
    public let proofStage4: Data
    public let leaf: String
    public let scopedNullifier: String
}

// MARK: - Proving Pipeline

public enum Pipeline {

    public static func run(
        pkpDir: String,
        data: PassportData,
        config: WitnessConfig
    ) throws -> PipelineResult {
        let pipelineStart = CFAbsoluteTimeGetCurrent()

        let tbsCert = data.tbsCertificate720.zeroPadded(to: Constants.maxTbsSize1300)

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
        print(String(format: "Commitments computed in %.2fs", elapsed(from: t)))

        let verity = try Verity(backend: .provekit)

        // Build typed witnesses for all stages
        let stage1 = Stage1Witness(
            cscKeyNeHash: cscKeyNeHash,
            cscPubkey: data.cscaModulus.toWitnessArray(),
            cscPubkeyRedcParam: data.cscaBarrett.toWitnessArray(),
            salt: "0x1",
            country: data.country,
            tbsCertificate: tbsCert.toWitnessArray(),
            dscSignature: data.cscaSignature.toWitnessArray(),
            tbsCertificateLen: String(data.tbsCertificateLen),
            exponent: String(data.cscaExponent)
        )

        let stage2 = Stage2Witness(
            commIn: commOut1,
            saltIn: "0x1",
            saltOut: "0x2",
            dg1: data.dg1Padded.toWitnessArray(),
            dscPubkey: data.dscModulus.toWitnessArray(),
            dscPubkeyRedcParam: data.dscBarrett.toWitnessArray(),
            dscPubkeyOffsetInDscCert: String(data.dscPubkeyOffset),
            exponent: String(data.dscExponent),
            exponentOffsetInDscCert: String(data.dscExponentOffset),
            sodSignature: data.sodSignature.toWitnessArray(),
            tbsCertificate: tbsCert.toWitnessArray(),
            signedAttributes: data.signedAttrs.toWitnessArray(),
            eContent: data.econtent.toWitnessArray()
        )

        let stage3 = Stage3Witness(
            commIn: commOut2,
            saltIn: "0x2",
            dg1: data.dg1Padded.toWitnessArray(),
            dg1PaddedLength: String(data.dg1Len),
            dg1HashOffset: String(data.dg1HashOffset),
            signedAttributes: data.signedAttrs.toWitnessArray(),
            signedAttributesSize: String(data.signedAttributesSize),
            eContent: data.econtent.toWitnessArray(),
            eContentLen: String(data.econtentLen),
            privateNullifier: privateNullifier,
            rDg1: config.rDg1
        )

        let stage4 = Stage4Witness(
            root: testMerkleRoot,
            sodHash: sodHash,
            dg1: data.dg1Padded.toWitnessArray(),
            rDg1: config.rDg1,
            serviceScope: config.serviceScope,
            serviceSubscope: config.serviceSubscope,
            currentDate: String(config.currentDate),
            leafIndex: config.leafIndex,
            merklePath: config.merklePath,
            minAgeRequired: String(config.minAgeRequired),
            maxAgeRequired: String(config.maxAgeRequired),
            nullifierSecret: config.nullifierSecret
        )

        let stages: [(name: String, witness: any Encodable, label: String)] = [
            ("t_add_dsc_1300", stage1, "comm_out=\(String(commOut1.prefix(18)))"),
            ("t_add_id_data_1300", stage2, "comm_out=\(String(commOut2.prefix(18)))"),
            ("t_add_integrity_commit", stage3, "leaf=\(String(leaf.prefix(18)))"),
            ("t_attest", stage4, "nullifier="),
        ]

        var proofs: [Data] = []

        for (i, (name, witness, label)) in stages.enumerated() {
            let witnessJson = try WitnessEncoder.encode(witness)
            t = CFAbsoluteTimeGetCurrent()
            let prover = try loadProver(verity: verity, pkpDir: pkpDir, name: name)
            let loadTime = elapsed(from: t)
            t = CFAbsoluteTimeGetCurrent()
            let proof = try prover.prove(witness: Witness(json: witnessJson))
            prover.close()
            proofs.append(proof.data)
            print(String(format: "[%d/4] %-22@ done in %.2fs (load %.2fs)  %@",
                          i + 1, name as NSString, elapsed(from: t), loadTime, label as NSString))
        }

        let scopedNullifier = CommitmentComputer.computeScopedNullifier(
            dg1: data.dg1Padded, econtent: data.econtent,
            serviceScope: config.serviceScope, serviceSubscope: config.serviceSubscope,
            nullifierSecret: config.nullifierSecret
        )

        let totalTime = elapsed(from: pipelineStart)
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

    // MARK: - Private Helpers

    private static func elapsed(from start: CFAbsoluteTime) -> Double {
        CFAbsoluteTimeGetCurrent() - start
    }

    private static func loadProver(verity: Verity, pkpDir: String, name: String) throws -> ProverScheme {
        let url = URL(fileURLWithPath: pkpDir).appendingPathComponent("\(name)-prover.pkp")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw PassportError.dataNotFound("Prover file not found: \(url.path)")
        }
        return try verity.loadProver(from: url.path)
    }
}
