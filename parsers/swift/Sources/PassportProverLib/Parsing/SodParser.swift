import Foundation

/// Parses CMS SignedData (SOD) from ePassport.
public enum SodParser {

    /// CMS content type OIDs
    private static let oidSignedData = "1.2.840.113549.1.7.2"
    private static let oidContentType = "1.2.840.113549.1.9.3"
    private static let oidMessageDigest = "1.2.840.113549.1.9.4"
    private static let oidSigningTime = "1.2.840.113549.1.9.5"

    public static func parse(rawBytes: Data) throws -> SOD {
        let bytes = stripLengthPrefix(rawBytes)

        // Parse outer ContentInfo: SEQUENCE { contentType OID, [0] content }
        let (outerSeq, _) = try ASN1.parse(bytes)
        guard outerSeq.tag == ASN1.tagSequence else {
            throw PassportError.cmsParsingFailed("Expected SEQUENCE for ContentInfo")
        }

        let contentInfoChildren = try ASN1.parseSequence(outerSeq.data)
        guard contentInfoChildren.count >= 2 else {
            throw PassportError.cmsParsingFailed("ContentInfo must have at least 2 elements")
        }

        // Verify content type is signedData
        let contentTypeOid = ASN1.parseOID(contentInfoChildren[0].data)
        guard contentTypeOid == oidSignedData else {
            throw PassportError.cmsParsingFailed("Expected SignedData OID, got \(contentTypeOid)")
        }

        // [0] EXPLICIT tagged content
        let contentWrapper = contentInfoChildren[1]
        guard ASN1.isContextTag(contentWrapper, number: 0) else {
            throw PassportError.cmsParsingFailed("Expected [0] context tag for SignedData content")
        }

        // Parse SignedData SEQUENCE
        let (signedDataSeq, _) = try ASN1.parse(contentWrapper.data)
        guard signedDataSeq.tag == ASN1.tagSequence else {
            throw PassportError.cmsParsingFailed("Expected SEQUENCE for SignedData")
        }

        let sdChildren = try ASN1.parseSequence(signedDataSeq.data)
        guard sdChildren.count >= 4 else {
            throw PassportError.cmsParsingFailed("SignedData must have at least 4 elements")
        }

        // version INTEGER
        let version = ASN1.parseIntValue(sdChildren[0].data)

        // digestAlgorithms SET OF AlgorithmIdentifier
        let digestAlgorithms = try parseDigestAlgorithms(sdChildren[1])

        // encapContentInfo SEQUENCE
        let encapContent = try parseEncapContent(sdChildren[2])

        // Find certificates [0] and signerInfos SET
        var certificate: DSC?
        var signerInfo: SignerInfo?

        for i in 3 ..< sdChildren.count {
            let child = sdChildren[i]
            if ASN1.isContextTag(child, number: 0) {
                // certificates [0] IMPLICIT SET OF Certificate
                certificate = try parseCertificate(child.data)
            } else if child.tag == ASN1.tagSet {
                // signerInfos SET OF SignerInfo
                signerInfo = try parseSignerInfo(child.data)
            }
        }

        guard let cert = certificate else {
            throw PassportError.missingRequiredField("DSC certificate")
        }
        guard let si = signerInfo else {
            throw PassportError.missingRequiredField("SignerInfo")
        }

        return SOD(
            version: version,
            digestAlgorithms: digestAlgorithms,
            encapContentInfo: encapContent,
            signerInfo: si,
            certificate: cert,
            bytes: bytes
        )
    }

    private static func stripLengthPrefix(_ data: Data) -> Data {
        if data.count >= 4 && data[data.startIndex] == 0x77 && data[data.startIndex + 1] == 0x82 {
            return Data(data[(data.startIndex + 4)...])
        }
        return data
    }

    private static func parseDigestAlgorithms(_ node: ASN1Node) throws -> [DigestAlgorithm] {
        let algNodes = try ASN1.parseSequence(node.data)
        return try algNodes.map { algNode in
            let algChildren = try ASN1.parseSequence(algNode.data)
            guard !algChildren.isEmpty, algChildren[0].tag == ASN1.tagOID else {
                throw PassportError.asn1DecodingFailed("Expected OID in AlgorithmIdentifier")
            }
            let oid = ASN1.parseOID(algChildren[0].data)
            guard let alg = DigestAlgorithm.fromOid(oid) else {
                throw PassportError.asn1DecodingFailed("Unsupported digest algorithm: \(oid)")
            }
            return alg
        }
    }

    private static func parseEncapContent(_ node: ASN1Node) throws -> EContent {
        guard node.tag == ASN1.tagSequence else {
            throw PassportError.cmsParsingFailed("Expected SEQUENCE for EncapsulatedContentInfo")
        }

        let children = try ASN1.parseSequence(node.data)
        guard children.count >= 2 else {
            throw PassportError.missingRequiredField("eContent")
        }

        // children[0] is contentType OID, children[1] is [0] EXPLICIT eContent
        guard ASN1.isContextTag(children[1], number: 0) else {
            throw PassportError.missingRequiredField("eContent")
        }

        // Inside [0], there's an OCTET STRING containing the LDS SecurityObject
        let (eContentOctet, _) = try ASN1.parse(children[1].data)
        let eContentBytes: Data
        if eContentOctet.tag == ASN1.tagOctetString {
            eContentBytes = eContentOctet.data
        } else {
            eContentBytes = children[1].data
        }

        // Parse the LDS Security Object: SEQUENCE { version, hashAlg, dgHashValues }
        let (ldsSeq, _) = try ASN1.parse(eContentBytes)
        let ldsChildren = try ASN1.parseSequence(ldsSeq.data)
        guard ldsChildren.count >= 3 else {
            throw PassportError.asn1DecodingFailed("LDS Security Object needs at least 3 elements")
        }

        let ldsVersion = ASN1.parseIntValue(ldsChildren[0].data)

        // Hash algorithm
        let hashAlgChildren = try ASN1.parseSequence(ldsChildren[1].data)
        guard !hashAlgChildren.isEmpty else {
            throw PassportError.asn1DecodingFailed("Empty hash algorithm identifier")
        }
        let hashOid = ASN1.parseOID(hashAlgChildren[0].data)
        guard let hashAlgorithm = DigestAlgorithm.fromOid(hashOid) else {
            throw PassportError.asn1DecodingFailed("Unsupported hash algorithm: \(hashOid)")
        }

        // Data group hash values
        let dgHashSeqChildren = try ASN1.parseSequence(ldsChildren[2].data)
        var dgHashValues: [Int: Data] = [:]
        for dgHashNode in dgHashSeqChildren {
            let dgFields = try ASN1.parseSequence(dgHashNode.data)
            guard dgFields.count >= 2 else { continue }
            let dgNumber = ASN1.parseIntValue(dgFields[0].data)
            let dgHash = dgFields[1].data
            dgHashValues[dgNumber] = dgHash
        }

        return EContent(
            version: ldsVersion,
            hashAlgorithm: hashAlgorithm,
            dataGroupHashValues: DataGroupHashValues(values: dgHashValues),
            bytes: eContentBytes
        )
    }

    private static func parseCertificate(_ data: Data) throws -> DSC {
        // certificates [0] contains one or more Certificate SEQUENCE nodes
        let certNodes = try ASN1.parseSequence(data)
        guard !certNodes.isEmpty else {
            throw PassportError.missingRequiredField("DSC certificate")
        }
        return try DscParser.parse(certNode: certNodes[0])
    }

    private static func parseSignerInfo(_ data: Data) throws -> SignerInfo {
        // SET contains one or more SignerInfo SEQUENCE
        let siNodes = try ASN1.parseSequence(data)
        guard !siNodes.isEmpty else {
            throw PassportError.dataNotFound("No SignerInfo found")
        }

        let siChildren = try ASN1.parseSequence(siNodes[0].data)
        guard siChildren.count >= 5 else {
            throw PassportError.cmsParsingFailed("SignerInfo must have at least 5 elements")
        }

        let siVersion = ASN1.parseIntValue(siChildren[0].data)

        // siChildren[1] = signerIdentifier (skip)
        // siChildren[2] = digestAlgorithm
        let digestAlgChildren = try ASN1.parseSequence(siChildren[2].data)
        guard !digestAlgChildren.isEmpty else {
            throw PassportError.asn1DecodingFailed("Empty digest algorithm in SignerInfo")
        }
        let digestOid = ASN1.parseOID(digestAlgChildren[0].data)
        guard let digestAlg = DigestAlgorithm.fromOid(digestOid) else {
            throw PassportError.asn1DecodingFailed("Unsupported digest algorithm: \(digestOid)")
        }

        // Find signedAttrs [0], signatureAlgorithm, and signature
        var signedAttrsNode: ASN1Node?
        var sigAlgNode: ASN1Node?
        var signatureNode: ASN1Node?

        var idx = 3
        while idx < siChildren.count {
            let child = siChildren[idx]
            if ASN1.isContextTag(child, number: 0) {
                signedAttrsNode = child
            } else if child.tag == ASN1.tagSequence && sigAlgNode == nil {
                sigAlgNode = child
            } else if child.tag == ASN1.tagOctetString {
                signatureNode = child
            }
            idx += 1
        }

        guard let attrsNode = signedAttrsNode else {
            throw PassportError.missingRequiredField("signedAttrs")
        }
        guard let sigAlg = sigAlgNode else {
            throw PassportError.missingRequiredField("signatureAlgorithm in SignerInfo")
        }

        // Parse signature algorithm
        let sigAlgChildren = try ASN1.parseSequence(sigAlg.data)
        guard !sigAlgChildren.isEmpty else {
            throw PassportError.asn1DecodingFailed("Empty signature algorithm")
        }
        let sigAlgOid = ASN1.parseOID(sigAlgChildren[0].data)
        guard let sigAlgName = SignatureAlgorithmName.fromOid(sigAlgOid) else {
            throw PassportError.unsupportedSignatureAlgorithm(sigAlgOid)
        }
        let sigAlgParams = sigAlgChildren.count > 1 ? sigAlgChildren[1].data : nil
        let signatureAlgorithm = SignatureAlgorithm(name: sigAlgName, parameters: sigAlgParams)

        // Extract signature bytes
        let signatureData: Data
        if let sigNode = signatureNode {
            signatureData = sigNode.data
        } else {
            throw PassportError.missingRequiredField("signature in SignerInfo")
        }

        // Parse signed attributes
        let signedAttrs = try parseSignedAttrs(attrsNode)

        return SignerInfo(
            version: siVersion,
            signedAttrs: signedAttrs,
            digestAlgorithm: digestAlg,
            signatureAlgorithm: signatureAlgorithm,
            signature: signatureData
        )
    }

    private static func parseSignedAttrs(_ node: ASN1Node) throws -> SignedAttrs {
        let attrNodes = try ASN1.parseSequence(node.data)

        var contentType = ""
        var messageDigest: Data?
        var signingTime: Date?

        for attrNode in attrNodes {
            let attrChildren = try ASN1.parseSequence(attrNode.data)
            guard attrChildren.count >= 2 else { continue }
            guard attrChildren[0].tag == ASN1.tagOID else { continue }

            let oid = ASN1.parseOID(attrChildren[0].data)
            // attrChildren[1] is SET OF values
            let valuesChildren = try ASN1.parseSequence(attrChildren[1].data)
            guard !valuesChildren.isEmpty else { continue }

            switch oid {
            case oidContentType:
                if valuesChildren[0].tag == ASN1.tagOID {
                    contentType = OidRegistry.getName(ASN1.parseOID(valuesChildren[0].data))
                }
            case oidMessageDigest:
                // The value might be an OCTET STRING, get its raw DER encoding
                let rawNode = valuesChildren[0]
                messageDigest = ASN1.encodedBytes(tag: rawNode.tag, content: rawNode.data)
            case oidSigningTime:
                signingTime = ASN1.parseTime(valuesChildren[0])
            default:
                break
            }
        }

        guard let msgDigest = messageDigest else {
            throw PassportError.missingRequiredField("messageDigest")
        }

        // Re-encode signedAttrs as SET for signature verification
        let signedAttrsEncoded = ASN1.reencodeAsSet(node.data)

        return SignedAttrs(
            contentType: contentType,
            messageDigest: msgDigest,
            signingTime: signingTime,
            bytes: signedAttrsEncoded
        )
    }
}
