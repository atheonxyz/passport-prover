import XCTest
import BigInt
@testable import PassportProverLib

final class Poseidon2Tests: XCTestCase {

    // MARK: - Field Conversions

    func testHexToFieldBasic() {
        let result = Poseidon2.hexToField("0x1")
        XCTAssertEqual(result, BigUInt(1))
    }

    func testHexToFieldWithoutPrefix() {
        let result = Poseidon2.hexToField("ff")
        XCTAssertEqual(result, BigUInt(255))
    }

    func testHexToFieldReducesModP() {
        // P itself should reduce to 0
        let pHex = String(Poseidon2.P, radix: 16)
        let result = Poseidon2.hexToField(pHex)
        XCTAssertEqual(result, BigUInt(0))
    }

    func testFieldToHexPadsTo64Chars() {
        let hex = Poseidon2.fieldToHex(BigUInt(1))
        XCTAssertTrue(hex.hasPrefix("0x"))
        XCTAssertEqual(hex.count, 66) // "0x" + 64 hex chars
        XCTAssertTrue(hex.hasSuffix("1"))
    }

    func testFieldToHexRoundTrip() {
        let original = BigUInt(123456789)
        let hex = Poseidon2.fieldToHex(original)
        let recovered = Poseidon2.hexToField(hex)
        XCTAssertEqual(recovered, original)
    }

    // MARK: - Byte Packing

    func testPackBytesBasic() {
        let data = Data([0x01, 0x02, 0x03])
        let fields = Poseidon2.packBytesIntoFields(data)
        XCTAssertEqual(fields.count, 1)
        // 0x010203 = 66051
        XCTAssertEqual(fields[0], BigUInt(66051))
    }

    func testPackBytesMultipleFields() {
        // 32 bytes should produce 2 fields (31 + 1)
        let data = Data(repeating: 0x01, count: 32)
        let fields = Poseidon2.packBytesIntoFields(data)
        XCTAssertEqual(fields.count, 2)
    }

    func testPackBytesExactly31() {
        let data = Data(repeating: 0xAB, count: 31)
        let fields = Poseidon2.packBytesIntoFields(data)
        XCTAssertEqual(fields.count, 1)
    }

    // MARK: - Hash Determinism

    func testHashDeterministic() {
        let inputs: [BigUInt] = [BigUInt(1), BigUInt(2), BigUInt(3)]
        let hash1 = Poseidon2.hash(inputs)
        let hash2 = Poseidon2.hash(inputs)
        XCTAssertEqual(hash1, hash2)
    }

    func testHashDifferentInputsProduceDifferentOutputs() {
        let hash1 = Poseidon2.hash([BigUInt(1)])
        let hash2 = Poseidon2.hash([BigUInt(2)])
        XCTAssertNotEqual(hash1, hash2)
    }

    func testHashResultInField() {
        let result = Poseidon2.hash([BigUInt(42)])
        XCTAssertTrue(result < Poseidon2.P)
    }

    // MARK: - Known Test Vector

    func testHashSingleElement() {
        // Ensure hash of [0] produces a consistent non-zero result
        let result = Poseidon2.hash([BigUInt(0)])
        XCTAssertNotEqual(result, BigUInt(0))
        XCTAssertTrue(result < Poseidon2.P)
    }
}
