import Foundation

/// Extracted circuit inputs ready for ZK proof generation.
public struct PassportData: Sendable {
    public let dg1Padded: Data
    public let dg1Len: Int
    public let signedAttrs: Data
    public let signedAttributesSize: Int
    public let econtent: Data
    public let econtentLen: Int
    public let dscModulus: Data
    public let dscExponent: UInt64
    public let dscBarrett: Data
    public let sodSignature: Data
    public let cscaModulus: Data
    public let cscaExponent: UInt64
    public let cscaBarrett: Data
    public let cscaSignature: Data
    public let country: String
    public let dg1HashOffset: Int
    public let tbsCertificate720: Data
    public let tbsCertificateLen: Int
    public let dscPubkeyOffset: Int
    public let dscExponentOffset: Int

    public init(
        dg1Padded: Data, dg1Len: Int, signedAttrs: Data, signedAttributesSize: Int,
        econtent: Data, econtentLen: Int, dscModulus: Data, dscExponent: UInt64,
        dscBarrett: Data, sodSignature: Data, cscaModulus: Data, cscaExponent: UInt64,
        cscaBarrett: Data, cscaSignature: Data, country: String, dg1HashOffset: Int,
        tbsCertificate720: Data, tbsCertificateLen: Int, dscPubkeyOffset: Int,
        dscExponentOffset: Int
    ) {
        self.dg1Padded = dg1Padded
        self.dg1Len = dg1Len
        self.signedAttrs = signedAttrs
        self.signedAttributesSize = signedAttributesSize
        self.econtent = econtent
        self.econtentLen = econtentLen
        self.dscModulus = dscModulus
        self.dscExponent = dscExponent
        self.dscBarrett = dscBarrett
        self.sodSignature = sodSignature
        self.cscaModulus = cscaModulus
        self.cscaExponent = cscaExponent
        self.cscaBarrett = cscaBarrett
        self.cscaSignature = cscaSignature
        self.country = country
        self.dg1HashOffset = dg1HashOffset
        self.tbsCertificate720 = tbsCertificate720
        self.tbsCertificateLen = tbsCertificateLen
        self.dscPubkeyOffset = dscPubkeyOffset
        self.dscExponentOffset = dscExponentOffset
    }
}
