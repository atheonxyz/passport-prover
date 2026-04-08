import Foundation
import BigInt
import CryptoKit

public struct PassportReader: Sendable {
    private let dg1: Data
    private let sod: SOD
    private let cscaPublicKey: Data?

    public init(dg1: Data, sod: SOD, cscaPublicKey: Data? = nil) {
        self.dg1 = dg1
        self.sod = sod
        self.cscaPublicKey = cscaPublicKey
    }

    // MARK: - Public API

    public func extract() throws -> PassportData {
        let dg1Padded = try dg1.paddedToSize(Constants.maxDg1Size, label: "DG1")

        let (signedAttrs, signedAttrsSize) = try extractSignedAttrs()
        let (econtent, econtentLen, econtentRaw) = try extractEcontent()
        let (dscModulus, dscExponent, dscBarrett, sodSignature) = try extractDsc()
        let (cscaModulus, cscaExponent, cscaBarrett, cscaSignature) = try extractCsca()

        let dg1Hash = Self.sha256(dg1)
        let dg1HashOffset = try Self.findOffset(in: econtentRaw, of: dg1Hash, label: "DG1 hash in eContent")

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
        let dg1Hash = Self.sha256(dg1)
        guard let dg1FromEcontent = sod.encapContentInfo.dataGroupHashValues.values[1] else {
            throw PassportError.missingDg1Hash
        }

        if dg1Hash != dg1FromEcontent {
            throw PassportError.dg1HashMismatch
        }

        let econtentHash = Self.sha256(sod.encapContentInfo.bytes)
        var msgDigest = sod.signerInfo.signedAttrs.messageDigest
        // Strip OCTET STRING wrapper if present
        if msgDigest.count > 2, msgDigest[msgDigest.startIndex] == 0x04 {
            msgDigest = Data(msgDigest.dropFirst(2))
        }
        if econtentHash != msgDigest {
            throw PassportError.econtentHashMismatch
        }
    }

    // MARK: - Private Extraction

    private func extractSignedAttrs() throws -> (Data, Int) {
        let raw = sod.signerInfo.signedAttrs.bytes
        let padded = try raw.paddedToSize(Constants.maxSignedAttributesSize, label: "SignedAttributes")
        return (padded, raw.count)
    }

    private func extractEcontent() throws -> (Data, Int, Data) {
        let raw = sod.encapContentInfo.bytes
        let padded = try raw.paddedToSize(Constants.maxEcontentSize, label: "eContent")
        return (padded, raw.count, raw)
    }

    private func extractDsc() throws -> (Data, UInt64, Data, Data) {
        let pubKeyBytes = sod.certificate.tbs.subjectPublicKeyInfo.subjectPublicKey
        let (modulus, exponent) = try parseRSAPublicKey(pubKeyBytes)

        let modulusData = try Self.bigIntToFixedBytes(modulus, size: Constants.sigBytes, label: "DSC modulus")
        let barrett = try BarrettReduction.computeFixed(modulus: modulusData, size: Constants.sigBytes + 1)
        let signature = try sod.signerInfo.signature.paddedToSize(Constants.sigBytes, label: "SOD signature")

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
        let signature = try sod.certificate.signature.paddedToSize(cscaSize, label: "CSCA signature")

        return (modulusData, exponent, barrett, signature)
    }

    private func extractCountry() -> String {
        guard dg1.count >= 10 else { return "<<<" }
        let countryBytes = dg1[dg1.startIndex + 7 ..< dg1.startIndex + 10]
        return String(data: countryBytes, encoding: .ascii) ?? "<<<"
    }

    private func extractDscCert(dscModulus: Data, targetSize: Int) throws -> (Data, Int, Int) {
        let tbsBytes = sod.certificate.tbs.bytes
        let padded = try tbsBytes.paddedToSize(targetSize, label: "TBS certificate")
        let pubkeyOffset = try Self.findOffset(in: tbsBytes, of: dscModulus, label: "DSC modulus in TBS")
        return (padded, tbsBytes.count, pubkeyOffset)
    }

    // MARK: - RSA Key Parsing

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
            if children.count >= 2, children[0].tag == ASN1.tagSequence, children[1].tag == ASN1.tagBitString {
                let innerKeyData = DscParser.extractBitStringContent(children[1])
                return try parseRSAPublicKey(innerKeyData)
            }
        } catch {
            // Fall through to try raw format
        }
        return try parseRSAPublicKey(data)
    }

    // MARK: - Byte Search

    public static func findOffset(in haystack: Data, of needle: Data, label: String) throws -> Int {
        guard let range = haystack.range(of: needle) else {
            throw PassportError.dataNotFound(label)
        }
        return haystack.distance(from: haystack.startIndex, to: range.lowerBound)
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
        return try findOffset(in: Data(tbs.prefix(tbsLen)), of: minimal, label: "DSC exponent in TBS")
    }

    // MARK: - Utilities

    public static func bigIntToFixedBytes(_ value: BigUInt, size: Int, label: String) throws -> Data {
        let bytes = Data(value.serialize())
        guard bytes.count <= size else {
            throw PassportError.bufferOverflow("\(label): \(bytes.count) bytes exceeds \(size)")
        }
        var result = Data(count: size)
        let offset = size - bytes.count
        result.replaceSubrange(offset ..< offset + bytes.count, with: bytes)
        return result
    }

    // MARK: - SHA-256

    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}
