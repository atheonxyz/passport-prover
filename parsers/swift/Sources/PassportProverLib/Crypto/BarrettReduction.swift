import Foundation
import BigInt

public enum BarrettReduction: Sendable {

    private static let overflowBits = 4

    public static func compute(modulus: Data) -> Data {
        let n = BigUInt(modulus)
        let k = n.bitWidth
        let twoTo2k = BigUInt(1) << (2 * k + overflowBits)
        let mu = twoTo2k / n
        return Data(mu.serialize())
    }

    public static func computeFixed(modulus: Data, size: Int) throws -> Data {
        let mu = compute(modulus: modulus)
        guard mu.count <= size else {
            throw PassportError.bufferOverflow("Barrett parameter \(mu.count) bytes exceeds buffer \(size)")
        }
        var result = Data(count: size)
        let offset = size - mu.count
        result.replaceSubrange(offset ..< offset + mu.count, with: mu)
        return result
    }
}
