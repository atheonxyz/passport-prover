import XCTest
@testable import PassportProverLib

final class ASN1ParserTests: XCTestCase {

    // MARK: - TLV Parsing

    func testParseSimpleInteger() throws {
        // ASN.1 INTEGER encoding of value 42: 02 01 2A
        let data = Data([0x02, 0x01, 0x2A])
        let (node, nextOffset) = try ASN1.parse(data)

        XCTAssertEqual(node.tag, ASN1.tagInteger)
        XCTAssertEqual(node.data, Data([0x2A]))
        XCTAssertEqual(node.headerLength, 2)
        XCTAssertEqual(node.totalLength, 3)
        XCTAssertEqual(nextOffset, 3)
    }

    func testParseSequenceWithChildren() throws {
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        let data = Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        let (node, _) = try ASN1.parse(data)

        XCTAssertEqual(node.tag, ASN1.tagSequence)
        XCTAssertTrue(node.isConstructed)

        let children = try ASN1.parseSequence(node.data)
        XCTAssertEqual(children.count, 2)
        XCTAssertEqual(ASN1.parseIntValue(children[0].data), 1)
        XCTAssertEqual(ASN1.parseIntValue(children[1].data), 2)
    }

    func testParseEmptyDataThrows() {
        XCTAssertThrowsError(try ASN1.parse(Data())) { error in
            XCTAssertTrue(error is PassportError)
        }
    }

    func testParseTruncatedDataThrows() {
        // Tag says content is 10 bytes but data only has 2
        let data = Data([0x02, 0x0A, 0x01, 0x02])
        XCTAssertThrowsError(try ASN1.parse(data)) { error in
            XCTAssertTrue(error is PassportError)
        }
    }

    // MARK: - OID Parsing

    func testParseOID_SHA256() {
        // OID 2.16.840.1.101.3.4.2.1 (SHA-256)
        let oidBytes = Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
        let oid = ASN1.parseOID(oidBytes)
        XCTAssertEqual(oid, "2.16.840.1.101.3.4.2.1")
    }

    func testParseOID_RSA() {
        // OID 1.2.840.113549.1.1.1 (rsaEncryption)
        let oidBytes = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
        let oid = ASN1.parseOID(oidBytes)
        XCTAssertEqual(oid, "1.2.840.113549.1.1.1")
    }

    func testParseOIDEmpty() {
        XCTAssertEqual(ASN1.parseOID(Data()), "")
    }

    // MARK: - Integer Parsing

    func testParseIntegerBytesStripsLeadingZero() {
        let data = Data([0x00, 0xFF, 0xAB])
        let result = ASN1.parseIntegerBytes(data)
        XCTAssertEqual(result, Data([0xFF, 0xAB]))
    }

    func testParseIntegerBytesPreservesNonZeroLeading() {
        let data = Data([0x01, 0xFF])
        let result = ASN1.parseIntegerBytes(data)
        XCTAssertEqual(result, Data([0x01, 0xFF]))
    }

    func testParseIntValue() {
        let data = Data([0x01, 0x00, 0x01]) // 65537
        XCTAssertEqual(ASN1.parseIntValue(data), 65537)
    }

    // MARK: - Context Tags

    func testContextTagDetection() {
        let node = ASN1Node(tag: 0xA0, data: Data(), headerLength: 2, totalLength: 2)
        XCTAssertTrue(ASN1.isContextTag(node, number: 0))
        XCTAssertFalse(ASN1.isContextTag(node, number: 1))
    }

    // MARK: - DER Encoding

    func testEncodedBytesRoundTrip() throws {
        let content = Data([0x01, 0x02, 0x03])
        let encoded = ASN1.encodedBytes(tag: ASN1.tagOctetString, content: content)
        let (node, _) = try ASN1.parse(encoded)
        XCTAssertEqual(node.tag, ASN1.tagOctetString)
        XCTAssertEqual(node.data, content)
    }

    func testReencodeAsSet() throws {
        let content = Data([0x02, 0x01, 0x2A])
        let set = ASN1.reencodeAsSet(content)
        let (node, _) = try ASN1.parse(set)
        XCTAssertEqual(node.tag, ASN1.tagSet)
        XCTAssertEqual(node.data, content)
    }

    // MARK: - ASN1Node Properties

    func testRawTLVReencoding() throws {
        let original = Data([0x02, 0x03, 0x01, 0x00, 0x01])
        let (node, _) = try ASN1.parse(original)
        XCTAssertEqual(node.rawTLV, original)
    }

    func testNodeEquality() {
        let a = ASN1Node(tag: 0x02, data: Data([0x2A]), headerLength: 2, totalLength: 3)
        let b = ASN1Node(tag: 0x02, data: Data([0x2A]), headerLength: 2, totalLength: 3)
        let c = ASN1Node(tag: 0x02, data: Data([0x2B]), headerLength: 2, totalLength: 3)
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }
}
