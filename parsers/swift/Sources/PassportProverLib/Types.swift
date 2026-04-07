import Foundation

public enum DigestAlgorithm: String {
    case sha1, sha224, sha256, sha384, sha512

    public static func fromOid(_ oid: String) -> DigestAlgorithm? {
        switch oid {
        case "1.3.14.3.2.26": return .sha1
        case "2.16.840.1.101.3.4.2.4": return .sha224
        case "2.16.840.1.101.3.4.2.1": return .sha256
        case "2.16.840.1.101.3.4.2.2": return .sha384
        case "2.16.840.1.101.3.4.2.3": return .sha512
        default: return nil
        }
    }
}

public enum SignatureAlgorithmName: String {
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

    public static func fromOid(_ oid: String) -> SignatureAlgorithmName? {
        switch oid {
        case "1.2.840.113549.1.1.5": return .sha1WithRSA
        case "1.2.840.113549.1.1.11": return .sha256WithRSA
        case "1.2.840.113549.1.1.12": return .sha384WithRSA
        case "1.2.840.113549.1.1.13": return .sha512WithRSA
        case "1.2.840.113549.1.1.10": return .rsassaPSS
        case "1.2.840.10045.4.1": return .ecdsaWithSHA1
        case "1.2.840.10045.4.3.2": return .ecdsaWithSHA256
        case "1.2.840.10045.4.3.3": return .ecdsaWithSHA384
        case "1.2.840.10045.4.3.4": return .ecdsaWithSHA512
        case "1.2.840.113549.1.1.1": return .rsaEncryption
        case "1.2.840.10045.2.1": return .ecPublicKey
        default: return nil
        }
    }
}

public struct SignatureAlgorithm {
    public let name: SignatureAlgorithmName
    public let parameters: Data?

    public init(name: SignatureAlgorithmName, parameters: Data? = nil) {
        self.name = name
        self.parameters = parameters
    }
}

public struct DataGroupHashValues {
    public let values: [Int: Data]

    public init(values: [Int: Data]) {
        self.values = values
    }
}

public struct EContent {
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

public struct SignedAttrs {
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

public struct SignerInfo {
    public let version: Int
    public let signedAttrs: SignedAttrs
    public let digestAlgorithm: DigestAlgorithm
    public let signatureAlgorithm: SignatureAlgorithm
    public let signature: Data

    public init(version: Int, signedAttrs: SignedAttrs, digestAlgorithm: DigestAlgorithm, signatureAlgorithm: SignatureAlgorithm, signature: Data) {
        self.version = version
        self.signedAttrs = signedAttrs
        self.digestAlgorithm = digestAlgorithm
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }
}

public struct SubjectPublicKeyInfo {
    public let algorithm: SignatureAlgorithm
    public let subjectPublicKey: Data

    public init(algorithm: SignatureAlgorithm, subjectPublicKey: Data) {
        self.algorithm = algorithm
        self.subjectPublicKey = subjectPublicKey
    }
}

public struct TbsCertificate {
    public let version: Int
    public let serialNumber: Data
    public let signatureAlgorithm: SignatureAlgorithm
    public let issuer: String
    public let validityNotBefore: Date
    public let validityNotAfter: Date
    public let subject: String
    public let subjectPublicKeyInfo: SubjectPublicKeyInfo
    public let bytes: Data

    public init(version: Int, serialNumber: Data, signatureAlgorithm: SignatureAlgorithm, issuer: String, validityNotBefore: Date, validityNotAfter: Date, subject: String, subjectPublicKeyInfo: SubjectPublicKeyInfo, bytes: Data) {
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

public struct DSC {
    public let tbs: TbsCertificate
    public let signatureAlgorithm: SignatureAlgorithm
    public let signature: Data

    public init(tbs: TbsCertificate, signatureAlgorithm: SignatureAlgorithm, signature: Data) {
        self.tbs = tbs
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }
}

public struct SOD {
    public let version: Int
    public let digestAlgorithms: [DigestAlgorithm]
    public let encapContentInfo: EContent
    public let signerInfo: SignerInfo
    public let certificate: DSC
    public let bytes: Data

    public init(version: Int, digestAlgorithms: [DigestAlgorithm], encapContentInfo: EContent, signerInfo: SignerInfo, certificate: DSC, bytes: Data) {
        self.version = version
        self.digestAlgorithms = digestAlgorithms
        self.encapContentInfo = encapContentInfo
        self.signerInfo = signerInfo
        self.certificate = certificate
        self.bytes = bytes
    }
}

public struct PassportData {
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
}
