package verity.passport.prover

/**
 * Sealed hierarchy of errors that can occur while parsing or verifying an ePassport document.
 *
 * All errors extend [IllegalArgumentException] following the convention established by
 * kotlinx.serialization's `SerializationException`: these failures are fundamentally caused
 * by invalid or unexpected input data, not by programming mistakes.
 *
 * Domain-specific data is exposed as typed `val` properties so callers can inspect the
 * failing value without parsing the message string.
 */
public sealed class PassportError(message: String) : IllegalArgumentException(message) {

    /** Indicates that the hash of DG1 stored in eContent does not match the computed hash. */
    public class Dg1HashMismatch : PassportError("DG1 hash mismatch in eContent")

    /** Indicates that the hash of eContent stored in SignedAttributes does not match the computed hash. */
    public class EcontentHashMismatch : PassportError("eContent hash mismatch in SignedAttributes")

    /** Indicates that a data item exceeded the maximum allowed buffer size. */
    public class BufferOverflow(
        public val detail: String,
    ) : PassportError("Data too large for buffer: $detail")

    /** Indicates that a required piece of data could not be located in the structure. */
    public class DataNotFound(
        public val detail: String,
    ) : PassportError("Required data not found: $detail")

    /** Indicates that the signature algorithm OID is not supported by this implementation. */
    public class UnsupportedSignatureAlgorithm(
        public val algorithm: String,
    ) : PassportError("Unsupported signature algorithm: $algorithm")

    /** Indicates a failure while decoding the CMS (Cryptographic Message Syntax) structure. */
    public class CmsParsingFailed(
        public val detail: String,
    ) : PassportError("CMS parsing failed: $detail")

    /** Indicates a failure while decoding an ASN.1 structure. */
    public class Asn1DecodingFailed(
        public val detail: String,
    ) : PassportError("ASN.1 decoding failed: $detail")

    /** Indicates that a mandatory field was absent from the parsed structure. */
    public class MissingRequiredField(
        public val field: String,
    ) : PassportError("Missing required field: $field")

    /** Indicates that the DG1 hash entry is absent from the eContent hash table. */
    public class MissingDg1Hash : PassportError("Missing DG1 hash in eContent")
}
