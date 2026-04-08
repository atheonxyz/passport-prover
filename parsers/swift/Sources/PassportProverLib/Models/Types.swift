import Foundation

// MARK: - Digest Algorithms

public enum DigestAlgorithm: String, Sendable, Hashable, CaseIterable {
    case sha1, sha224, sha256, sha384, sha512

    private static let oidLookup: [String: DigestAlgorithm] = [
        "1.3.14.3.2.26": .sha1,
        "2.16.840.1.101.3.4.2.4": .sha224,
        "2.16.840.1.101.3.4.2.1": .sha256,
        "2.16.840.1.101.3.4.2.2": .sha384,
        "2.16.840.1.101.3.4.2.3": .sha512,
    ]

    public static func fromOid(_ oid: String) -> DigestAlgorithm? {
        oidLookup[oid]
    }
}

// MARK: - Signature Algorithms

public enum SignatureAlgorithmName: String, Sendable, Hashable, CaseIterable {
    case sha1WithRSA
    case sha256WithRSA
    case sha384WithRSA
    case sha512WithRSA
    case rsassaPSS
    case ecdsaWithSHA1
    case ecdsaWithSHA256
    case ecdsaWithSHA384
    case ecdsaWithSHA512
    case rsaEncryption
    case ecPublicKey

    private static let oidLookup: [String: SignatureAlgorithmName] = [
        "1.2.840.113549.1.1.5": .sha1WithRSA,
        "1.2.840.113549.1.1.11": .sha256WithRSA,
        "1.2.840.113549.1.1.12": .sha384WithRSA,
        "1.2.840.113549.1.1.13": .sha512WithRSA,
        "1.2.840.113549.1.1.10": .rsassaPSS,
        "1.2.840.10045.4.1": .ecdsaWithSHA1,
        "1.2.840.10045.4.3.2": .ecdsaWithSHA256,
        "1.2.840.10045.4.3.3": .ecdsaWithSHA384,
        "1.2.840.10045.4.3.4": .ecdsaWithSHA512,
        "1.2.840.113549.1.1.1": .rsaEncryption,
        "1.2.840.10045.2.1": .ecPublicKey,
    ]

    public static func fromOid(_ oid: String) -> SignatureAlgorithmName? {
        oidLookup[oid]
    }
}

public struct SignatureAlgorithm: Sendable, Equatable {
    public let name: SignatureAlgorithmName
    public let parameters: Data?

    public init(name: SignatureAlgorithmName, parameters: Data? = nil) {
        self.name = name
        self.parameters = parameters
    }
}

// MARK: - X.509 Certificate Types

public struct SubjectPublicKeyInfo: Sendable, Equatable {
    public let algorithm: SignatureAlgorithm
    public let subjectPublicKey: Data

    public init(algorithm: SignatureAlgorithm, subjectPublicKey: Data) {
        self.algorithm = algorithm
        self.subjectPublicKey = subjectPublicKey
    }
}

public struct TbsCertificate: Sendable {
    public let version: Int
    public let serialNumber: Data
    public let signatureAlgorithm: SignatureAlgorithm
    public let issuer: String
    public let validityNotBefore: Date
    public let validityNotAfter: Date
    public let subject: String
    public let subjectPublicKeyInfo: SubjectPublicKeyInfo
    public let bytes: Data

    public init(
        version: Int, serialNumber: Data, signatureAlgorithm: SignatureAlgorithm,
        issuer: String, validityNotBefore: Date, validityNotAfter: Date,
        subject: String, subjectPublicKeyInfo: SubjectPublicKeyInfo, bytes: Data
    ) {
        self.version = version
        self.serialNumber = serialNumber
        self.signatureAlgorithm = signatureAlgorithm
        self.issuer = issuer
        self.validityNotBefore = validityNotBefore
        self.validityNotAfter = validityNotAfter
        self.subject = subject
        self.subjectPublicKeyInfo = subjectPublicKeyInfo
        self.bytes = bytes
    }
}

/// Document Signing Certificate extracted from CMS SignedData.
public struct DSC: Sendable {
    public let tbs: TbsCertificate
    public let signatureAlgorithm: SignatureAlgorithm
    public let signature: Data

    public init(tbs: TbsCertificate, signatureAlgorithm: SignatureAlgorithm, signature: Data) {
        self.tbs = tbs
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }
}

// MARK: - CMS SignedData Types

public struct DataGroupHashValues: Sendable, Equatable {
    public let values: [Int: Data]

    public init(values: [Int: Data]) {
        self.values = values
    }
}

public struct EContent: Sendable {
    public let version: Int
    public let hashAlgorithm: DigestAlgorithm
    public let dataGroupHashValues: DataGroupHashValues
    public let bytes: Data

    public init(version: Int, hashAlgorithm: DigestAlgorithm, dataGroupHashValues: DataGroupHashValues, bytes: Data) {
        self.version = version
        self.hashAlgorithm = hashAlgorithm
        self.dataGroupHashValues = dataGroupHashValues
        self.bytes = bytes
    }
}

public struct SignedAttrs: Sendable {
    public let contentType: String
    public let messageDigest: Data
    public let signingTime: Date?
    public let bytes: Data

    public init(contentType: String, messageDigest: Data, signingTime: Date?, bytes: Data) {
        self.contentType = contentType
        self.messageDigest = messageDigest
        self.signingTime = signingTime
        self.bytes = bytes
    }
}

public struct SignerInfo: Sendable {
    public let version: Int
    public let signedAttrs: SignedAttrs
    public let digestAlgorithm: DigestAlgorithm
    public let signatureAlgorithm: SignatureAlgorithm
    public let signature: Data

    public init(
        version: Int, signedAttrs: SignedAttrs, digestAlgorithm: DigestAlgorithm,
        signatureAlgorithm: SignatureAlgorithm, signature: Data
    ) {
        self.version = version
        self.signedAttrs = signedAttrs
        self.digestAlgorithm = digestAlgorithm
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }
}

/// Security Object Document - the top-level CMS SignedData structure from ePassport SOD.
public struct SOD: Sendable {
    public let version: Int
    public let digestAlgorithms: [DigestAlgorithm]
    public let encapContentInfo: EContent
    public let signerInfo: SignerInfo
    public let certificate: DSC
    public let bytes: Data

    public init(
        version: Int, digestAlgorithms: [DigestAlgorithm], encapContentInfo: EContent,
        signerInfo: SignerInfo, certificate: DSC, bytes: Data
    ) {
        self.version = version
        self.digestAlgorithms = digestAlgorithms
        self.encapContentInfo = encapContentInfo
        self.signerInfo = signerInfo
        self.certificate = certificate
        self.bytes = bytes
    }
}

// MARK: - Circuit Input Data

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
