import Foundation

/// Parses X.509 certificates (DSC) from CMS SignedData.
public enum DscParser {

    /// Parse a Certificate ASN1Node (the full SEQUENCE containing TBS, sigAlg, signature).
    public static func parse(certNode: ASN1Node) throws -> DSC {
        guard certNode.tag == ASN1.tagSequence else {
            throw PassportError.x509ParsingFailed("Expected SEQUENCE for Certificate")
        }

        let certChildren = try ASN1.parseSequence(certNode.data)
        guard certChildren.count >= 3 else {
            throw PassportError.x509ParsingFailed("Certificate must have at least 3 elements")
        }

        // TBS Certificate
        let tbsNode = certChildren[0]
        let tbsBytes = ASN1.encodedBytes(tag: tbsNode.tag, content: tbsNode.data)
        let tbs = try parseTBS(tbsNode)

        let tbsCert = TbsCertificate(
            version: tbs.version,
            serialNumber: tbs.serialNumber,
            signatureAlgorithm: tbs.signatureAlgorithm,
            issuer: tbs.issuer,
            validityNotBefore: tbs.notBefore,
            validityNotAfter: tbs.notAfter,
            subject: tbs.subject,
            subjectPublicKeyInfo: tbs.spki,
            bytes: tbsBytes
        )

        // Signature Algorithm
        let certSigAlg = try parseAlgorithmIdentifier(certChildren[1])

        // Signature Value (BIT STRING)
        let signatureData = extractBitStringContent(certChildren[2])

        return DSC(
            tbs: tbsCert,
            signatureAlgorithm: certSigAlg,
            signature: signatureData
        )
    }

    /// Parse from raw DER bytes of a certificate.
    public static func parse(derBytes: Data) throws -> DSC {
        let (certNode, _) = try ASN1.parse(derBytes)
        return try parse(certNode: certNode)
    }

    private struct TBSResult {
        let version: Int
        let serialNumber: Data
        let signatureAlgorithm: SignatureAlgorithm
        let issuer: String
        let notBefore: Date
        let notAfter: Date
        let subject: String
        let spki: SubjectPublicKeyInfo
    }

    private static func parseTBS(_ node: ASN1Node) throws -> TBSResult {
        let children = try ASN1.parseSequence(node.data)
        guard children.count >= 7 else {
            throw PassportError.x509ParsingFailed("TBSCertificate needs at least 7 elements")
        }

        var idx = 0

        // version [0] EXPLICIT INTEGER (optional)
        var version = 0
        if ASN1.isContextTag(children[idx], number: 0) {
            let (versionNode, _) = try ASN1.parse(children[idx].data)
            version = ASN1.parseIntValue(versionNode.data)
            idx += 1
        }

        // serialNumber INTEGER
        let serialNumber = ASN1.parseIntegerBytes(children[idx].data)
        idx += 1

        // signature AlgorithmIdentifier
        let tbsSigAlg = try parseAlgorithmIdentifier(children[idx])
        idx += 1

        // issuer Name
        let issuer = try formatX500Name(children[idx])
        idx += 1

        // validity SEQUENCE { notBefore, notAfter }
        let validityChildren = try ASN1.parseSequence(children[idx].data)
        guard validityChildren.count >= 2 else {
            throw PassportError.x509ParsingFailed("Validity must have notBefore and notAfter")
        }
        let notBefore = ASN1.parseTime(validityChildren[0]) ?? Date.distantPast
        let notAfter = ASN1.parseTime(validityChildren[1]) ?? Date.distantFuture
        idx += 1

        // subject Name
        let subject = try formatX500Name(children[idx])
        idx += 1

        // subjectPublicKeyInfo SEQUENCE
        let spki = try parseSubjectPublicKeyInfo(children[idx])

        return TBSResult(
            version: version,
            serialNumber: serialNumber,
            signatureAlgorithm: tbsSigAlg,
            issuer: issuer,
            notBefore: notBefore,
            notAfter: notAfter,
            subject: subject,
            spki: spki
        )
    }

    static func parseAlgorithmIdentifier(_ node: ASN1Node) throws -> SignatureAlgorithm {
        let children = try ASN1.parseSequence(node.data)
        guard !children.isEmpty, children[0].tag == ASN1.tagOID else {
            throw PassportError.asn1DecodingFailed("Expected OID in AlgorithmIdentifier")
        }
        let oid = ASN1.parseOID(children[0].data)
        guard let name = SignatureAlgorithmName.fromOid(oid) else {
            throw PassportError.unsupportedSignatureAlgorithm(oid)
        }
        let params = children.count > 1 && children[1].tag != ASN1.tagNull ? children[1].data : nil
        return SignatureAlgorithm(name: name, parameters: params)
    }

    private static func parseSubjectPublicKeyInfo(_ node: ASN1Node) throws -> SubjectPublicKeyInfo {
        let children = try ASN1.parseSequence(node.data)
        guard children.count >= 2 else {
            throw PassportError.x509ParsingFailed("SubjectPublicKeyInfo needs algorithm and key")
        }

        let algorithm = try parseAlgorithmIdentifier(children[0])
        let publicKeyData = extractBitStringContent(children[1])

        return SubjectPublicKeyInfo(algorithm: algorithm, subjectPublicKey: publicKeyData)
    }

    static func extractBitStringContent(_ node: ASN1Node) -> Data {
        guard node.tag == ASN1.tagBitString, !node.data.isEmpty else {
            return node.data
        }
        // First byte is number of unused bits, skip it
        return Data(node.data.dropFirst())
    }

    private static func formatX500Name(_ node: ASN1Node) throws -> String {
        let rdnSeqs = try ASN1.parseSequence(node.data)
        var parts: [String] = []

        for rdnSet in rdnSeqs {
            let atvs = try ASN1.parseSequence(rdnSet.data)
            for atv in atvs {
                let atvChildren = try ASN1.parseSequence(atv.data)
                guard atvChildren.count >= 2 else { continue }
                let oid = ASN1.parseOID(atvChildren[0].data)
                let fieldName = OidRegistry.getName(oid)
                let value = ASN1.parseString(atvChildren[1])
                parts.append("\(fieldName)=\(value)")
            }
        }

        return parts.joined(separator: ", ")
    }
}
