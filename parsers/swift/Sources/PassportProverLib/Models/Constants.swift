import Foundation

public enum Constants {
    public static let maxSignedAttributesSize = 200
    public static let maxDg1Size = 95
    public static let sigBytes = 256
    public static let maxEcontentSize = 200
    public static let maxTbsSize = 720
    public static let maxTbsSize1300 = 1400
    public static let chunk1Size = 640
    public static let treeDepth = 24

    /// RSA_NE_H domain separator for csc_key_ne_hash.
    public static let rsaKeyNeHashDomain = "0x5253415f4e455f48"

    public static let zeroField = "0x0000000000000000000000000000000000000000000000000000000000000000"
}
