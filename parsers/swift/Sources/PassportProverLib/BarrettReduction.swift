import Foundation
import BigInt

public enum BarrettReduction {

    private static let overflowBits = 4

    public static func compute(modulus: Data) -> Data {
        let n = BigUInt(modulus)
        let k = n.bitWidth
        let twoTo2k = BigUInt(1) << (2 * k + overflowBits)
        let mu = twoTo2k / n

        let muBytes = mu.serialize()
        return Data(muBytes)
    }

    public static func computeFixed(modulus: Data, size: Int) throws -> Data {
        let mu = compute(modulus: modulus)
        if mu.count > size {
            throw PassportError.bufferOverflow("Barrett parameter \(mu.count) bytes exceeds buffer \(size)")
        }
        var result = Data(count: size)
        let offset = size - mu.count
        result.replaceSubrange(offset ..< offset + mu.count, with: mu)
        return result
    }
}
