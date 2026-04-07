import Foundation

/// Minimal DER/ASN.1 parser for CMS SignedData and X.509 certificates.
public struct ASN1Node {
    public let tag: UInt8
    public let data: Data
    public let headerLength: Int
    public let totalLength: Int

    /// The full TLV (tag + length + value) encoding of this node.
    public var fullData: Data {
        let start = data.startIndex - headerLength
        return Data(data[start ..< data.startIndex]) + data
    }

    public var isConstructed: Bool { tag & 0x20 != 0 }
    public var tagClass: UInt8 { tag >> 6 }
    public var tagNumber: UInt8 { tag & 0x1F }
}

public enum ASN1 {

    // MARK: - Tag constants
    public static let tagInteger: UInt8 = 0x02
    public static let tagBitString: UInt8 = 0x03
    public static let tagOctetString: UInt8 = 0x04
    public static let tagNull: UInt8 = 0x05
    public static let tagOID: UInt8 = 0x06
    public static let tagUTF8String: UInt8 = 0x0C
    public static let tagPrintableString: UInt8 = 0x13
    public static let tagIA5String: UInt8 = 0x16
    public static let tagUTCTime: UInt8 = 0x17
    public static let tagGeneralizedTime: UInt8 = 0x18
    public static let tagSequence: UInt8 = 0x30
    public static let tagSet: UInt8 = 0x31

    // MARK: - Parse TLV

    /// Parse one ASN.1 TLV at the given offset.
    /// Returns the parsed node and the offset just past this TLV.
    public static func parse(_ data: Data, at offset: Int = 0) throws -> (ASN1Node, Int) {
        guard offset < data.count else {
            throw PassportError.asn1DecodingFailed("Unexpected end of data at offset \(offset)")
        }

        let tag = data[data.startIndex + offset]
        var pos = offset + 1

        guard pos < data.count else {
            throw PassportError.asn1DecodingFailed("Missing length at offset \(pos)")
        }

        let (length, lengthBytes) = try parseLength(data, at: pos)
        pos += lengthBytes

        let headerLen = 1 + lengthBytes
        guard pos + length <= data.count else {
            throw PassportError.asn1DecodingFailed("Content exceeds data bounds: offset=\(pos), length=\(length), total=\(data.count)")
        }

        let content = data[(data.startIndex + pos) ..< (data.startIndex + pos + length)]
        let node = ASN1Node(tag: tag, data: Data(content), headerLength: headerLen, totalLength: headerLen + length)
        return (node, pos + length)
    }

    /// Parse all children of a constructed node.
    public static func parseSequence(_ data: Data) throws -> [ASN1Node] {
        var children: [ASN1Node] = []
        var offset = 0
        while offset < data.count {
            let (node, next) = try parse(data, at: offset)
            children.append(node)
            offset = next
        }
        return children
    }

    /// Parse DER length encoding.
    static func parseLength(_ data: Data, at offset: Int) throws -> (Int, Int) {
        let base = data.startIndex + offset
        guard base < data.endIndex else {
            throw PassportError.asn1DecodingFailed("Missing length byte")
        }

        let first = data[base]
        if first < 0x80 {
            return (Int(first), 1)
        }

        let numBytes = Int(first & 0x7F)
        guard numBytes > 0 && numBytes <= 4 else {
            throw PassportError.asn1DecodingFailed("Unsupported length encoding: \(numBytes) bytes")
        }
        guard base + numBytes < data.endIndex else {
            throw PassportError.asn1DecodingFailed("Length bytes exceed data")
        }

        var length = 0
        for i in 1 ... numBytes {
            length = (length << 8) | Int(data[base + i])
        }
        return (length, 1 + numBytes)
    }

    // MARK: - Value extraction

    /// Parse an OID from its DER content bytes.
    public static func parseOID(_ data: Data) -> String {
        guard !data.isEmpty else { return "" }

        var components: [UInt64] = []
        let first = data[data.startIndex]
        components.append(UInt64(first / 40))
        components.append(UInt64(first % 40))

        var value: UInt64 = 0
        for i in 1 ..< data.count {
            let byte = data[data.startIndex + i]
            value = (value << 7) | UInt64(byte & 0x7F)
            if byte & 0x80 == 0 {
                components.append(value)
                value = 0
            }
        }

        return components.map { String($0) }.joined(separator: ".")
    }

    /// Extract an integer value from an ASN.1 INTEGER node's content bytes.
    public static func parseIntValue(_ data: Data) -> Int {
        var result = 0
        for byte in data {
            result = (result << 8) | Int(byte)
        }
        return result
    }

    /// Extract big-endian unsigned bytes from an ASN.1 INTEGER, stripping leading zero.
    public static func parseIntegerBytes(_ data: Data) -> Data {
        if data.count > 1 && data[data.startIndex] == 0x00 {
            return Data(data[(data.startIndex + 1)...])
        }
        return data
    }

    /// Parse a string value (UTF8, PrintableString, IA5String, etc.)
    public static func parseString(_ node: ASN1Node) -> String {
        switch node.tag {
        case tagUTF8String, tagPrintableString, tagIA5String:
            return String(data: node.data, encoding: .utf8) ?? node.data.hexString
        default:
            return node.data.hexString
        }
    }

    /// Parse UTCTime or GeneralizedTime to Date.
    public static func parseTime(_ node: ASN1Node) -> Date? {
        guard let str = String(data: node.data, encoding: .ascii) else { return nil }

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")

        if node.tag == tagUTCTime {
            formatter.dateFormat = "yyMMddHHmmss'Z'"
            return formatter.date(from: str)
        } else if node.tag == tagGeneralizedTime {
            formatter.dateFormat = "yyyyMMddHHmmss'Z'"
            return formatter.date(from: str)
        }
        return nil
    }

    /// Get the raw DER encoding of a node including its tag and length.
    public static func encodedBytes(tag: UInt8, content: Data) -> Data {
        var result = Data([tag])
        result.append(encodeLength(content.count))
        result.append(content)
        return result
    }

    /// Re-encode a SET as DER (tag 0x31) from its inner content.
    public static func reencodeAsSet(_ content: Data) -> Data {
        encodedBytes(tag: tagSet, content: content)
    }

    static func encodeLength(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        }
        var len = length
        var bytes: [UInt8] = []
        while len > 0 {
            bytes.insert(UInt8(len & 0xFF), at: 0)
            len >>= 8
        }
        var result = Data([0x80 | UInt8(bytes.count)])
        result.append(contentsOf: bytes)
        return result
    }

    // MARK: - Context-tagged helpers

    /// Check if a node is context-tagged with [n] (explicit).
    public static func isContextTag(_ node: ASN1Node, number: UInt8) -> Bool {
        node.tag == (0xA0 | number)
    }
}

// MARK: - Data hex extension

extension Data {
    public var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    public init?(hexString: String) {
        let hex = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
