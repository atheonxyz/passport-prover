package verity.passport.prover

sealed class PassportError(message: String) : Exception(message) {
    class Dg1HashMismatch : PassportError("DG1 hash mismatch in eContent")
    class EcontentHashMismatch : PassportError("eContent hash mismatch in SignedAttributes")
    class BufferOverflow(detail: String) : PassportError("Data too large for buffer: $detail")
    class DataNotFound(detail: String) : PassportError("Required data not found: $detail")
    class UnsupportedSignatureAlgorithm(alg: String) : PassportError("Unsupported signature algorithm: $alg")
    class CmsParsingFailed(detail: String) : PassportError("CMS parsing failed: $detail")
    class Asn1DecodingFailed(detail: String) : PassportError("ASN.1 decoding failed: $detail")
    class MissingRequiredField(field: String) : PassportError("Missing required field: $field")
    class MissingDg1Hash : PassportError("Missing DG1 hash in eContent")
}
