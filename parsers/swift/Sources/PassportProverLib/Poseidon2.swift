import Foundation
import BigInt

/// Poseidon2 sponge hash over BN254 scalar field.
/// Ported directly from the Kotlin implementation.
public enum Poseidon2 {

    public static let P = BigUInt("21888242871839275222246405745257275088548364400416034343698204186575808495617")

    private static let ZERO = BigUInt(0)
    private static let RATE = 3
    private static let TWO_POW_64 = BigUInt(1) << 64

    private static func add(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
        (a + b) % P
    }

    private static func mul(_ a: BigUInt, _ b: BigUInt) -> BigUInt {
        (a * b) % P
    }

    private static func sBox(_ x: BigUInt) -> BigUInt {
        let s = mul(x, x)
        return mul(mul(s, s), x)
    }

    private static func matMul4x4(_ state: inout [BigUInt]) {
        let t0 = add(state[0], state[1])
        let t1 = add(state[2], state[3])
        var t2 = add(state[1], state[1])
        t2 = add(t2, t1)
        var t3 = add(state[3], state[3])
        t3 = add(t3, t0)
        var t4 = add(t1, t1)
        t4 = add(t4, t4)
        t4 = add(t4, t3)
        var t5 = add(t0, t0)
        t5 = add(t5, t5)
        t5 = add(t5, t2)
        let t6 = add(t3, t5)
        let t7 = add(t2, t4)
        state[0] = t6
        state[1] = t5
        state[2] = t7
        state[3] = t4
    }

    private static func internalMatMul(_ state: inout [BigUInt], _ diag: [BigUInt]) {
        var sum = ZERO
        for s in state { sum = add(sum, s) }
        for i in state.indices {
            state[i] = add(mul(state[i], diag[i]), sum)
        }
    }

    public static func permutation(_ inputs: [BigUInt]) -> [BigUInt] {
        let rfFirst = 4
        let rp = 56
        let pEnd = rfFirst + rp
        let numRounds = rfFirst + rp + rfFirst

        var state = inputs
        let rc = Poseidon2Constants.roundConstants
        let diag = Poseidon2Constants.internalMatrixDiagonal

        matMul4x4(&state)

        for r in 0 ..< rfFirst {
            for i in 0 ... 3 { state[i] = add(state[i], rc[r][i]) }
            for i in 0 ... 3 { state[i] = sBox(state[i]) }
            matMul4x4(&state)
        }

        for r in rfFirst ..< pEnd {
            state[0] = add(state[0], rc[r][0])
            state[0] = sBox(state[0])
            internalMatMul(&state, diag)
        }

        for r in pEnd ..< numRounds {
            for i in 0 ... 3 { state[i] = add(state[i], rc[r][i]) }
            for i in 0 ... 3 { state[i] = sBox(state[i]) }
            matMul4x4(&state)
        }

        return state
    }

    public static func hash(_ inputs: [BigUInt]) -> BigUInt {
        let iv = mul(BigUInt(inputs.count) , TWO_POW_64)

        var state: [BigUInt] = [ZERO, ZERO, ZERO, iv]
        var cache: [BigUInt] = [ZERO, ZERO, ZERO]
        var cacheSize = 0

        for input in inputs {
            if cacheSize == RATE {
                for i in 0 ..< RATE { state[i] = add(state[i], cache[i]) }
                cache = [ZERO, ZERO, ZERO]
                cacheSize = 0
                state = permutation(state)
            }
            cache[cacheSize] = input
            cacheSize += 1
        }

        for i in 0 ..< cacheSize { state[i] = add(state[i], cache[i]) }
        let result = permutation(state)

        return result[0]
    }

    public static func hash(_ hexInputs: String...) -> BigUInt {
        hash(hexInputs.map { hexToField($0) })
    }

    public static func hexToField(_ hex: String) -> BigUInt {
        let s = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        return BigUInt(s, radix: 16)! % P
    }

    public static func fieldToHex(_ fe: BigUInt) -> String {
        let reduced = fe % P
        let hex = String(reduced, radix: 16)
        return "0x" + String(repeating: "0", count: max(0, 64 - hex.count)) + hex
    }

    public static func packBytesIntoFields(_ bytes: Data, bytesPerField: Int = 31) -> [BigUInt] {
        let numFields = (bytes.count + bytesPerField - 1) / bytesPerField
        var fields: [BigUInt] = []

        let firstFieldSize = bytes.count - (numFields - 1) * bytesPerField
        var offset = 0

        var value = ZERO
        for _ in 0 ..< firstFieldSize {
            value = (value << 8) + BigUInt(bytes[bytes.startIndex + offset])
            offset += 1
        }
        fields.append(value % P)

        for _ in 1 ..< numFields {
            value = ZERO
            for _ in 0 ..< bytesPerField {
                value = (value << 8) + BigUInt(bytes[bytes.startIndex + offset])
                offset += 1
            }
            fields.append(value % P)
        }

        return fields.reversed()
    }

    /// Convenience: pack [UInt8] array.
    public static func packBytesIntoFields(_ bytes: [UInt8], bytesPerField: Int = 31) -> [BigUInt] {
        packBytesIntoFields(Data(bytes), bytesPerField: bytesPerField)
    }
}
