import Foundation

// MARK: - Hex Encoding

extension Data {
    /// Hex-encode bytes as a lowercase string.
    public var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Initialize from a hex string, optionally prefixed with "0x".
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

// MARK: - Witness Serialization

extension Data {
    /// Convert each byte to its string representation for witness arrays.
    public func toWitnessArray() -> [String] {
        map(String.init)
    }
}

// MARK: - Padding

extension Data {
    /// Zero-pad data to a fixed buffer size, throwing on overflow.
    public func paddedToSize(_ size: Int, label: String) throws -> Data {
        guard count <= size else {
            throw PassportError.bufferOverflow("\(label): \(count) bytes exceeds buffer \(size)")
        }
        var result = Data(count: size)
        result.replaceSubrange(0 ..< count, with: self)
        return result
    }

    /// Zero-pad data to a target size (non-throwing, returns self if already large enough).
    public func zeroPadded(to targetSize: Int) -> Data {
        guard count < targetSize else { return self }
        var padded = Data(count: targetSize)
        padded.replaceSubrange(0 ..< count, with: self)
        return padded
    }
}
