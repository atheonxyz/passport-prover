import Foundation
import BigInt

/// Computes Poseidon2 commitment values natively, matching the Noir circuits.
/// These chain stages together: comm_out from stage N = comm_in for stage N+1.
public enum CommitmentComputer {

    /// Stage 1: hash(salt, country, tbs_certificate)
    public static func computeStage1CommOut(
        salt: String,
        country: String,
        tbsCertificate: Data
    ) -> String {
        var fields: [BigUInt] = []
        fields.append(Poseidon2.hexToField(salt))
        fields.append(contentsOf: Poseidon2.packBytesIntoFields(Data(country.utf8)))
        fields.append(contentsOf: Poseidon2.packBytesIntoFields(tbsCertificate))
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    /// Stage 2: hash(salt, country, signed_attrs, size, dg1, econtent, nullifier)
    public static func computeStage2CommOut(
        saltOut: String,
        country: String,
        signedAttributes: Data,
        signedAttributesSize: Int,
        dg1: Data,
        econtent: Data,
        privateNullifier: String
    ) -> String {
        var fields: [BigUInt] = []
        fields.append(Poseidon2.hexToField(saltOut))
        fields.append(contentsOf: Poseidon2.packBytesIntoFields(Data(country.utf8)))
        fields.append(contentsOf: Poseidon2.packBytesIntoFields(signedAttributes))
        fields.append(BigUInt(signedAttributesSize))
        fields.append(contentsOf: Poseidon2.packBytesIntoFields(dg1))
        fields.append(contentsOf: Poseidon2.packBytesIntoFields(econtent))
        fields.append(Poseidon2.hexToField(privateNullifier))
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    /// Compute h_dg1 = Poseidon2([r_dg1, packed_dg1...])
    public static func computeHDg1(rDg1: String, dg1: Data) -> BigUInt {
        var fields: [BigUInt] = []
        fields.append(Poseidon2.hexToField(rDg1))
        fields.append(contentsOf: Poseidon2.packBytesIntoFields(dg1))
        return Poseidon2.hash(fields)
    }

    /// Stage 3 leaf: Poseidon2([h_dg1, sod_hash])
    public static func computeLeaf(rDg1: String, dg1: Data, econtent: Data) -> String {
        let hDg1 = computeHDg1(rDg1: rDg1, dg1: dg1)
        let sodHash = Poseidon2.hash(Poseidon2.packBytesIntoFields(econtent))
        return Poseidon2.fieldToHex(Poseidon2.hash([hDg1, sodHash]))
    }

    /// Stage 4: scoped nullifier for service-specific unlinkability.
    public static func computeScopedNullifier(
        dg1: Data,
        econtent: Data,
        serviceScope: String,
        serviceSubscope: String,
        nullifierSecret: String
    ) -> String {
        let sodHash = Poseidon2.hash(Poseidon2.packBytesIntoFields(econtent))

        var nullFields: [BigUInt] = []
        nullFields.append(contentsOf: Poseidon2.packBytesIntoFields(dg1))
        nullFields.append(sodHash)
        let privateNullifier = Poseidon2.hash(nullFields)

        var scopeFields: [BigUInt] = [
            privateNullifier,
            Poseidon2.hexToField(serviceScope),
            Poseidon2.hexToField(serviceSubscope),
        ]
        if nullifierSecret != Constants.zeroField {
            scopeFields.append(Poseidon2.hexToField(nullifierSecret))
        }
        return Poseidon2.fieldToHex(Poseidon2.hash(scopeFields))
    }
}
