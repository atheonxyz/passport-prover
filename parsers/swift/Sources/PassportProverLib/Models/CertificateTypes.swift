import Foundation

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
