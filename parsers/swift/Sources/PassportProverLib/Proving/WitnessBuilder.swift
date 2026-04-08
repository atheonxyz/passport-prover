import Foundation
import BigInt

/// Poseidon2-based commitment helpers and partial SHA-256 for circuit witness building.
public enum WitnessBuilder {

    // MARK: - Poseidon2 Commitments

    public static func computePrivateNullifier(dg1: Data, econtent: Data, sodSignature: Data) -> String {
        var fields: [BigUInt] = []
        fields.append(contentsOf: Poseidon2.packBytesIntoFields(dg1))
        fields.append(contentsOf: Poseidon2.packBytesIntoFields(econtent))
        fields.append(contentsOf: Poseidon2.packBytesIntoFields(sodSignature))
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    public static func computeSodHash(econtent: Data) -> String {
        let fields = Poseidon2.packBytesIntoFields(econtent)
        return Poseidon2.fieldToHex(Poseidon2.hash(fields))
    }

    public static func computeCscKeyNeHash(cscaPubkey: Data, cscaExponent: UInt64) -> String {
        let domain = Poseidon2.hexToField(Constants.rsaKeyNeHashDomain)
        let packedPubkey = Poseidon2.packBytesIntoFields(cscaPubkey)
        let exponentBytes = Data([
            UInt8((cscaExponent >> 24) & 0xFF),
            UInt8((cscaExponent >> 16) & 0xFF),
            UInt8((cscaExponent >> 8) & 0xFF),
            UInt8(cscaExponent & 0xFF),
        ])
        let packedExponent = Poseidon2.packBytesIntoFields(exponentBytes, bytesPerField: 31)

        var hashInput: [BigUInt] = [domain]
        hashInput.append(contentsOf: packedPubkey)
        hashInput.append(contentsOf: packedExponent)
        return Poseidon2.fieldToHex(Poseidon2.hash(hashInput))
    }

    public static func computeTestMerkleRoot(leaf: String) -> String {
        var current = Poseidon2.hexToField(leaf)
        for _ in 0 ..< Constants.treeDepth {
            current = Poseidon2.hash([current, BigUInt(0)])
        }
        return Poseidon2.fieldToHex(current)
    }

    // MARK: - Partial SHA-256

    /// Process 64-byte blocks through SHA-256 compression without finalization.
    /// Used for circuit-compatible partial hash computation.
    public static func partialSha256(chunk: Data) -> [Int32] {
        precondition(chunk.count % 64 == 0, "Chunk must be multiple of 64 bytes, got \(chunk.count)")

        var state: [Int32] = [
            0x6a09e667, -0x44a93649, 0x3c6ef372, -0x5ab00ac6,
            0x510e527f, -0x64fa9774, 0x1f83d9ab, 0x5be0cd19
        ]

        let bytes = [UInt8](chunk)
        for blockStart in stride(from: 0, to: bytes.count, by: 64) {
            var w = [Int32](repeating: 0, count: 64)
            for i in 0 ..< 16 {
                let off = blockStart + i * 4
                w[i] = (Int32(bytes[off]) << 24) | (Int32(bytes[off + 1]) << 16) |
                        (Int32(bytes[off + 2]) << 8) | Int32(bytes[off + 3])
            }
            for i in 16 ..< 64 {
                let s0 = rotateRight(w[i - 15], 7) ^ rotateRight(w[i - 15], 18) ^ (w[i - 15] >>> 3)
                let s1 = rotateRight(w[i - 2], 17) ^ rotateRight(w[i - 2], 19) ^ (w[i - 2] >>> 10)
                w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
            }
            var a = state[0], b = state[1], c = state[2], d = state[3]
            var e = state[4], f = state[5], g = state[6], h = state[7]
            for i in 0 ..< 64 {
                let s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
                let ch = (e & f) ^ (~e & g)
                let temp1 = h &+ s1 &+ ch &+ sha256K[i] &+ w[i]
                let s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let temp2 = s0 &+ maj
                h = g; g = f; f = e; e = d &+ temp1
                d = c; c = b; b = a; a = temp1 &+ temp2
            }
            state[0] &+= a; state[1] &+= b; state[2] &+= c; state[3] &+= d
            state[4] &+= e; state[5] &+= f; state[6] &+= g; state[7] &+= h
        }

        return state
    }

    private static func rotateRight(_ value: Int32, _ count: Int) -> Int32 {
        Int32(bitPattern: (UInt32(bitPattern: value) >> count) | (UInt32(bitPattern: value) << (32 - count)))
    }

    private static let sha256K: [Int32] = [
        0x428a2f98, 0x71374491, -0x4a3f0431, -0x164a245b,
        0x3956c25b, 0x59f111f1, -0x6dc07d5c, -0x54e3a12b,
        -0x27f85568, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, -0x7f214e02, -0x6423f959, -0x3e640e8c,
        -0x1b64963f, -0x1041b87a, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        -0x67c1aeae, -0x57ce3993, -0x4ffcd838, -0x40a68039,
        -0x391ff40d, -0x2a586eb9, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, -0x7e3d36d2, -0x6d8dd37b,
        -0x5d40175f, -0x57e599b5, -0x3db47490, -0x3893ae5d,
        -0x2e6d17e7, -0x2966f9dc, -0x0bf1ca7b, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, -0x7b3787ec, -0x7338fdf8,
        -0x6f410006, -0x5baf9315, -0x41065c09, -0x398e870e,
    ]
}

// MARK: - Unsigned Right Shift

/// Unsigned right shift for Int32 (equivalent to Java's `>>>`).
infix operator >>>: BitwiseShiftPrecedence
fileprivate func >>> (lhs: Int32, rhs: Int) -> Int32 {
    Int32(bitPattern: UInt32(bitPattern: lhs) >> rhs)
}
