import Foundation
import BigInt
import CommonCrypto

public struct PassportReader {
    private let dg1: Data
    private let sod: SOD
    private let cscaPublicKey: Data?

    public init(dg1: Data, sod: SOD, cscaPublicKey: Data? = nil) {
        self.dg1 = dg1
        self.sod = sod
        self.cscaPublicKey = cscaPublicKey
    }

    public func extract() throws -> PassportData {
        let dg1Padded = try Self.fitBytes(dg1, size: Constants.maxDg1Size, label: "DG1")

        let (signedAttrs, signedAttrsSize) = try extractSignedAttrs()
        let (econtent, econtentLen, econtentRaw) = try extractEcontent()
        let (dscModulus, dscExponent, dscBarrett, sodSignature) = try extractDsc()
        let (cscaModulus, cscaExponent, cscaBarrett, cscaSignature) = try extractCsca()

        let dg1Hash = sha256(dg1)
        let dg1HashOffset = try Self.findOffset(haystack: econtentRaw, needle: dg1Hash, label: "DG1 hash in eContent")

        let country = extractCountry()

        let (tbsCert, tbsCertLen, dscPubkeyOffset) = try extractDscCert(dscModulus: dscModulus, targetSize: Constants.maxTbsSize1300)

        let tbsBytes = sod.certificate.tbs.bytes
        let dscExponentOffset = try Self.findExponentOffset(tbs: tbsBytes, exponent: Int(dscExponent), tbsLen: tbsBytes.count)

        return PassportData(
            dg1Padded: dg1Padded,
            dg1Len: dg1.count,
            signedAttrs: signedAttrs,
            signedAttributesSize: signedAttrsSize,
            econtent: econtent,
            econtentLen: econtentLen,
            dscModulus: dscModulus,
            dscExponent: dscExponent,
            dscBarrett: dscBarrett,
            sodSignature: sodSignature,
            cscaModulus: cscaModulus,
            cscaExponent: cscaExponent,
            cscaBarrett: cscaBarrett,
            cscaSignature: cscaSignature,
            country: country,
            dg1HashOffset: dg1HashOffset,
            tbsCertificate720: tbsCert,
            tbsCertificateLen: tbsCertLen,
            dscPubkeyOffset: dscPubkeyOffset,
            dscExponentOffset: dscExponentOffset
        )
    }

    public func validate() throws {
        let dg1Hash = sha256(dg1)
        guard let dg1FromEcontent = sod.encapContentInfo.dataGroupHashValues.values[1] else {
            throw PassportError.missingDg1Hash
        }

        if dg1Hash != dg1FromEcontent {
            throw PassportError.dg1HashMismatch
        }

        let econtentHash = sha256(sod.encapContentInfo.bytes)
        var msgDigest = sod.signerInfo.signedAttrs.messageDigest
        // Strip OCTET STRING wrapper if present
        if msgDigest.count > 2 && msgDigest[msgDigest.startIndex] == 0x04 {
            msgDigest = Data(msgDigest.dropFirst(2))
        }
        if econtentHash != msgDigest {
            throw PassportError.econtentHashMismatch
        }
    }

    // MARK: - Private extraction methods

    private func extractSignedAttrs() throws -> (Data, Int) {
        let raw = sod.signerInfo.signedAttrs.bytes
        let padded = try Self.fitBytes(raw, size: Constants.maxSignedAttributesSize, label: "SignedAttributes")
        return (padded, raw.count)
    }

    private func extractEcontent() throws -> (Data, Int, Data) {
        let raw = sod.encapContentInfo.bytes
        let padded = try Self.fitBytes(raw, size: Constants.maxEcontentSize, label: "eContent")
        return (padded, raw.count, raw)
    }

    private func extractDsc() throws -> (Data, UInt64, Data, Data) {
        let pubKeyBytes = sod.certificate.tbs.subjectPublicKeyInfo.subjectPublicKey
        let (modulus, exponent) = try parseRSAPublicKey(pubKeyBytes)

        let modulusData = try Self.bigIntToFixedBytes(modulus, size: Constants.sigBytes, label: "DSC modulus")
        let barrett = try BarrettReduction.computeFixed(modulus: modulusData, size: Constants.sigBytes + 1)
        let signature = try Self.fitBytes(sod.signerInfo.signature, size: Constants.sigBytes, label: "SOD signature")

        return (modulusData, exponent, barrett, signature)
    }

    private func extractCsca() throws -> (Data, UInt64, Data, Data) {
        let cscaSize = Constants.sigBytes * 2

        guard let cscaKey = cscaPublicKey else {
            throw PassportError.dataNotFound("CSCA public key not provided")
        }

        let (modulus, exponent) = try parseRSAPublicKeyFromSPKI(cscaKey)
        let modulusData = try Self.bigIntToFixedBytes(modulus, size: cscaSize, label: "CSCA modulus")
        let barrett = try BarrettReduction.computeFixed(modulus: modulusData, size: cscaSize + 1)
        let signature = try Self.fitBytes(sod.certificate.signature, size: cscaSize, label: "CSCA signature")

        return (modulusData, exponent, barrett, signature)
    }

    private func extractCountry() -> String {
        if dg1.count >= 10 {
            let countryBytes = dg1[dg1.startIndex + 7 ..< dg1.startIndex + 10]
            return String(data: countryBytes, encoding: .ascii) ?? "<<<"
        }
        return "<<<"
    }

    private func extractDscCert(dscModulus: Data, targetSize: Int) throws -> (Data, Int, Int) {
        let tbsBytes = sod.certificate.tbs.bytes
        let padded = try Self.fitBytes(tbsBytes, size: targetSize, label: "TBS certificate")
        let pubkeyOffset = try Self.findOffset(haystack: tbsBytes, needle: dscModulus, label: "DSC modulus in TBS")
        return (padded, tbsBytes.count, pubkeyOffset)
    }

    // MARK: - RSA key parsing

    /// Parse RSA public key from raw PKCS#1 RSAPublicKey DER bytes.
    private func parseRSAPublicKey(_ data: Data) throws -> (BigUInt, UInt64) {
        let (node, _) = try ASN1.parse(data)
        let children = try ASN1.parseSequence(node.data)
        guard children.count >= 2 else {
            throw PassportError.invalidDscKey
        }
        let modulus = BigUInt(ASN1.parseIntegerBytes(children[0].data))
        let exponentInt = ASN1.parseIntValue(children[1].data)
        return (modulus, UInt64(exponentInt))
    }

    /// Parse RSA public key from SubjectPublicKeyInfo (SPKI) or raw PKCS#1 format.
    private func parseRSAPublicKeyFromSPKI(_ data: Data) throws -> (BigUInt, UInt64) {
        // Try SPKI first: SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
        do {
            let (outerNode, _) = try ASN1.parse(data)
            let children = try ASN1.parseSequence(outerNode.data)
            if children.count >= 2 && children[0].tag == ASN1.tagSequence && children[1].tag == ASN1.tagBitString {
                // SPKI format - extract inner RSA public key from BIT STRING
                let innerKeyData = DscParser.extractBitStringContent(children[1])
                return try parseRSAPublicKey(innerKeyData)
            }
        } catch {
            // Fall through to try raw format
        }
        // Try raw PKCS#1 RSAPublicKey format
        return try parseRSAPublicKey(data)
    }

    // MARK: - Utility methods

    public static func fitBytes(_ data: Data, size: Int, label: String) throws -> Data {
        if data.count > size {
            throw PassportError.bufferOverflow("\(label): \(data.count) bytes exceeds buffer \(size)")
        }
        var result = Data(count: size)
        result.replaceSubrange(0 ..< data.count, with: data)
        return result
    }

    public static func bigIntToFixedBytes(_ value: BigUInt, size: Int, label: String) throws -> Data {
        let bytes = Data(value.serialize())
        if bytes.count > size {
            throw PassportError.bufferOverflow("\(label): \(bytes.count) bytes exceeds \(size)")
        }
        var result = Data(count: size)
        let offset = size - bytes.count
        result.replaceSubrange(offset ..< offset + bytes.count, with: bytes)
        return result
    }

    public static func findExponentOffset(tbs: Data, exponent: Int, tbsLen: Int) throws -> Int {
        let expBE: [UInt8] = [
            UInt8((exponent >> 24) & 0xFF),
            UInt8((exponent >> 16) & 0xFF),
            UInt8((exponent >> 8) & 0xFF),
            UInt8(exponent & 0xFF),
        ]
        let start = expBE.firstIndex(where: { $0 != 0 }) ?? 3
        let minimal = Data(expBE[start...])
        return try findOffset(haystack: Data(tbs.prefix(tbsLen)), needle: minimal, label: "DSC exponent in TBS")
    }

    public static func findOffset(haystack: Data, needle: Data, label: String) throws -> Int {
        let haystackBytes = [UInt8](haystack)
        let needleBytes = [UInt8](needle)
        guard needleBytes.count <= haystackBytes.count else {
            throw PassportError.dataNotFound(label)
        }
        for i in 0 ... (haystackBytes.count - needleBytes.count) {
            var found = true
            for j in 0 ..< needleBytes.count {
                if haystackBytes[i + j] != needleBytes[j] {
                    found = false
                    break
                }
            }
            if found { return i }
        }
        throw PassportError.dataNotFound(label)
    }

    // MARK: - SHA-256

    private func sha256(_ data: Data) -> Data {
        Self.sha256(data)
    }

    public static func sha256(_ data: Data) -> Data {
        var hash = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { dataPtr in
            hash.withUnsafeMutableBytes { hashPtr in
                _ = CC_SHA256(dataPtr.baseAddress, CC_LONG(data.count), hashPtr.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        return hash
    }
}
