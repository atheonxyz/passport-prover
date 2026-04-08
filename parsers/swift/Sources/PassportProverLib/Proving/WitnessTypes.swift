import Foundation

// MARK: - Witness Configuration

public struct WitnessConfig: Sendable {
    public let salt1: String
    public let salt2: String
    public let rDg1: String
    public let currentDate: Int64
    public let minAgeRequired: Int
    public let maxAgeRequired: Int
    public let serviceScope: String
    public let serviceSubscope: String
    public let nullifierSecret: String
    public let merkleRoot: String
    public let leafIndex: String
    public let merklePath: [String]

    public init(
        salt1: String = "0x2",
        salt2: String = "0x3",
        rDg1: String = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        currentDate: Int64 = 1735689600,
        minAgeRequired: Int = 18,
        maxAgeRequired: Int = 0,
        serviceScope: String = Constants.zeroField,
        serviceSubscope: String = Constants.zeroField,
        nullifierSecret: String = Constants.zeroField,
        merkleRoot: String = Constants.zeroField,
        leafIndex: String = "0",
        merklePath: [String] = Array(repeating: Constants.zeroField, count: Constants.treeDepth)
    ) {
        self.salt1 = salt1
        self.salt2 = salt2
        self.rDg1 = rDg1
        self.currentDate = currentDate
        self.minAgeRequired = minAgeRequired
        self.maxAgeRequired = maxAgeRequired
        self.serviceScope = serviceScope
        self.serviceSubscope = serviceSubscope
        self.nullifierSecret = nullifierSecret
        self.merkleRoot = merkleRoot
        self.leafIndex = leafIndex
        self.merklePath = merklePath
    }
}

// MARK: - Stage Witnesses

/// DSC validation witness: verifies CSCA signature over TBS certificate.
public struct Stage1Witness: Encodable, Sendable {
    public let cscKeyNeHash: String
    public let cscPubkey: [String]
    public let cscPubkeyRedcParam: [String]
    public let salt: String
    public let country: String
    public let tbsCertificate: [String]
    public let dscSignature: [String]
    public let tbsCertificateLen: String
    public let exponent: String
}

/// ID data validation witness: verifies DSC signature over SOD.
public struct Stage2Witness: Encodable, Sendable {
    public let commIn: String
    public let saltIn: String
    public let saltOut: String
    public let dg1: [String]
    public let dscPubkey: [String]
    public let dscPubkeyRedcParam: [String]
    public let dscPubkeyOffsetInDscCert: String
    public let exponent: String
    public let exponentOffsetInDscCert: String
    public let sodSignature: [String]
    public let tbsCertificate: [String]
    public let signedAttributes: [String]
    public let eContent: [String]
}

/// Integrity commitment witness: binds DG1/eContent hashes into a leaf.
public struct Stage3Witness: Encodable, Sendable {
    public let commIn: String
    public let saltIn: String
    public let dg1: [String]
    public let dg1PaddedLength: String
    public let dg1HashOffset: String
    public let signedAttributes: [String]
    public let signedAttributesSize: String
    public let eContent: [String]
    public let eContentLen: String
    public let privateNullifier: String
    public let rDg1: String
}

/// Attestation witness: age checks, nullifier derivation, Merkle inclusion.
public struct Stage4Witness: Encodable, Sendable {
    public let root: String
    public let sodHash: String
    public let dg1: [String]
    public let rDg1: String
    public let serviceScope: String
    public let serviceSubscope: String
    public let currentDate: String
    public let leafIndex: String
    public let merklePath: [String]
    public let minAgeRequired: String
    public let maxAgeRequired: String
    public let nullifierSecret: String
}

// MARK: - Witness Encoder

public enum WitnessEncoder {

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.keyEncodingStrategy = .convertToSnakeCase
        return e
    }()

    public static func encode<W: Encodable>(_ witness: W) throws -> String {
        let data = try encoder.encode(witness)
        guard let json = String(data: data, encoding: .utf8) else {
            preconditionFailure("JSONEncoder produced non-UTF8 output")
        }
        return json
    }
}
