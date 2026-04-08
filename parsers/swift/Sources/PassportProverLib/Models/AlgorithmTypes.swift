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
