import XCTest
@testable import PassportProverLib

final class DataExtensionsTests: XCTestCase {

    // MARK: - Hex String

    func testHexStringEncoding() {
        let data = Data([0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertEqual(data.hexString, "deadbeef")
    }

    func testHexStringEmpty() {
        XCTAssertEqual(Data().hexString, "")
    }

    func testHexStringInitWithPrefix() {
        let data = Data(hexString: "0xDEAD")
        XCTAssertEqual(data, Data([0xDE, 0xAD]))
    }

    func testHexStringInitWithoutPrefix() {
        let data = Data(hexString: "BEEF")
        XCTAssertEqual(data, Data([0xBE, 0xEF]))
    }

    func testHexStringInitOddLengthReturnsNil() {
        XCTAssertNil(Data(hexString: "ABC"))
    }

    func testHexStringInitInvalidCharsReturnsNil() {
        XCTAssertNil(Data(hexString: "ZZZZ"))
    }

    func testHexStringRoundTrip() {
        let original = Data([0x00, 0x11, 0x22, 0x33, 0xFF])
        let hex = original.hexString
        let recovered = Data(hexString: hex)
        XCTAssertEqual(recovered, original)
    }

    // MARK: - Witness Array

    func testToWitnessArray() {
        let data = Data([0, 1, 255])
        XCTAssertEqual(data.toWitnessArray(), ["0", "1", "255"])
    }

    func testToWitnessArrayEmpty() {
        XCTAssertEqual(Data().toWitnessArray(), [])
    }

    // MARK: - Padding

    func testPaddedToSizeZeroPads() throws {
        let data = Data([0x01, 0x02])
        let padded = try data.paddedToSize(5, label: "test")
        XCTAssertEqual(padded.count, 5)
        XCTAssertEqual(padded[0], 0x01)
        XCTAssertEqual(padded[1], 0x02)
        XCTAssertEqual(padded[2], 0x00)
        XCTAssertEqual(padded[3], 0x00)
        XCTAssertEqual(padded[4], 0x00)
    }

    func testPaddedToSizeExactFit() throws {
        let data = Data([0x01, 0x02, 0x03])
        let padded = try data.paddedToSize(3, label: "test")
        XCTAssertEqual(padded, Data([0x01, 0x02, 0x03]))
    }

    func testPaddedToSizeOverflowThrows() {
        let data = Data([0x01, 0x02, 0x03])
        XCTAssertThrowsError(try data.paddedToSize(2, label: "test")) { error in
            XCTAssertEqual(error as? PassportError, .bufferOverflow("test: 3 bytes exceeds buffer 2"))
        }
    }

    func testZeroPaddedNonThrowing() {
        let data = Data([0x01])
        let padded = data.zeroPadded(to: 4)
        XCTAssertEqual(padded.count, 4)
        XCTAssertEqual(padded[0], 0x01)
        XCTAssertEqual(padded[1], 0x00)
    }

    func testZeroPaddedAlreadyLargeEnough() {
        let data = Data([0x01, 0x02, 0x03])
        let padded = data.zeroPadded(to: 2)
        XCTAssertEqual(padded, data)
    }
}
