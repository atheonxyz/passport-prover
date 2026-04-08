import Foundation

public enum PassportError: LocalizedError, Sendable, Equatable {
    case dg1HashMismatch
    case econtentHashMismatch
    case invalidDscKey
    case dscSignatureInvalid
    case cscaSignatureInvalid
    case bufferOverflow(String)
    case rsaExponentTooLarge
    case dataNotFound(String)
    case unsupportedSignatureAlgorithm(String)
    case cmsParsingFailed(String)
    case x509ParsingFailed(String)
    case asn1DecodingFailed(String)
    case missingRequiredField(String)
    case missingDg1Hash

    public var errorDescription: String? {
        switch self {
        case .dg1HashMismatch: return "DG1 hash mismatch in eContent"
        case .econtentHashMismatch: return "eContent hash mismatch in SignedAttributes"
        case .invalidDscKey: return "Invalid DSC public key"
        case .dscSignatureInvalid: return "DSC signature verification failed"
        case .cscaSignatureInvalid: return "CSCA signature verification failed"
        case .bufferOverflow(let d): return "Data too large for buffer: \(d)"
        case .rsaExponentTooLarge: return "RSA exponent too large"
        case .dataNotFound(let d): return "Required data not found: \(d)"
        case .unsupportedSignatureAlgorithm(let a): return "Unsupported signature algorithm: \(a)"
        case .cmsParsingFailed(let d): return "CMS parsing failed: \(d)"
        case .x509ParsingFailed(let d): return "X.509 certificate parsing failed: \(d)"
        case .asn1DecodingFailed(let d): return "ASN.1 decoding failed: \(d)"
        case .missingRequiredField(let f): return "Missing required field: \(f)"
        case .missingDg1Hash: return "Missing DG1 hash in eContent"
        }
    }
}
