package verity.passport.prover

/**
 * Internal registry that maps ASN.1 OID strings to human-readable names.
 * Covers PKCS#9 signed-attribute OIDs, ICAO MRTD OIDs, hash-algorithm OIDs,
 * X.509 RDN attribute OIDs, and common X.509 extension OIDs.
 *
 * If an OID is not present in the registry, [getName] returns the raw OID string unchanged.
 */
internal object OidRegistry {

    private val registry = mapOf(
        // PKCS#9 signed attributes
        "1.2.840.113549.1.9.3" to "contentType",
        "1.2.840.113549.1.9.4" to "messageDigest",
        "1.2.840.113549.1.9.5" to "signingTime",

        // ICAO MRTD
        "2.23.136.1.1.1" to "mRTDSignatureData",

        // Hash algorithms
        "1.3.14.3.2.26" to "SHA-1",
        "2.16.840.1.101.3.4.2.1" to "SHA-256",
        "2.16.840.1.101.3.4.2.2" to "SHA-384",
        "2.16.840.1.101.3.4.2.3" to "SHA-512",
        "2.16.840.1.101.3.4.2.4" to "SHA-224",

        // X.509 RDN attributes
        "2.5.4.3" to "commonName",
        "2.5.4.4" to "surname",
        "2.5.4.5" to "serialNumber",
        "2.5.4.6" to "countryName",
        "2.5.4.7" to "localityName",
        "2.5.4.8" to "stateOrProvinceName",
        "2.5.4.9" to "streetAddress",
        "2.5.4.10" to "organizationName",
        "2.5.4.11" to "organizationalUnitName",
        "2.5.4.12" to "title",
        "2.5.4.13" to "description",
        "2.5.4.17" to "postalCode",
        "2.5.4.42" to "givenName",
        "2.5.4.43" to "initials",
        "2.5.4.46" to "dnQualifier",
        "2.5.4.65" to "pseudonym",

        // X.509 extensions
        "2.5.29.14" to "subjectKeyIdentifier",
        "2.5.29.15" to "keyUsage",
        "2.5.29.17" to "subjectAltName",
        "2.5.29.19" to "basicConstraints",
        "2.5.29.31" to "cRLDistributionPoints",
        "2.5.29.32" to "certificatePolicies",
        "2.5.29.35" to "authorityKeyIdentifier",
        "2.5.29.37" to "extKeyUsage",
    )

    @JvmStatic
    internal fun getName(oid: String): String = registry[oid] ?: oid
}
