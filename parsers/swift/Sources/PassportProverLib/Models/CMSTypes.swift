import Foundation

// MARK: - CMS SignedData Types

public struct DataGroupHashValues: Sendable, Equatable {
    public let values: [Int: Data]

    public init(values: [Int: Data]) {
        self.values = values
    }
}

/// Encapsulated content from the LDS Security Object.
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
