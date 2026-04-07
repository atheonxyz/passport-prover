import Foundation

public enum OidRegistry {

    private static let registry: [String: String] = [
        // PKCS#9 signed attributes
        "1.2.840.113549.1.9.3": "contentType",
        "1.2.840.113549.1.9.4": "messageDigest",
        "1.2.840.113549.1.9.5": "signingTime",

        // ICAO MRTD
        "2.23.136.1.1.1": "mRTDSignatureData",

        // Hash algorithms
        "1.3.14.3.2.26": "SHA-1",
        "2.16.840.1.101.3.4.2.1": "SHA-256",
        "2.16.840.1.101.3.4.2.2": "SHA-384",
        "2.16.840.1.101.3.4.2.3": "SHA-512",
        "2.16.840.1.101.3.4.2.4": "SHA-224",

        // X.509 RDN attributes
        "2.5.4.3": "commonName",
        "2.5.4.4": "surname",
        "2.5.4.5": "serialNumber",
        "2.5.4.6": "countryName",
        "2.5.4.7": "localityName",
        "2.5.4.8": "stateOrProvinceName",
        "2.5.4.9": "streetAddress",
        "2.5.4.10": "organizationName",
        "2.5.4.11": "organizationalUnitName",
        "2.5.4.12": "title",
        "2.5.4.13": "description",
        "2.5.4.17": "postalCode",
        "2.5.4.42": "givenName",
        "2.5.4.43": "initials",
        "2.5.4.46": "dnQualifier",
        "2.5.4.65": "pseudonym",

        // X.509 extensions
        "2.5.29.14": "subjectKeyIdentifier",
        "2.5.29.15": "keyUsage",
        "2.5.29.17": "subjectAltName",
        "2.5.29.19": "basicConstraints",
        "2.5.29.31": "cRLDistributionPoints",
        "2.5.29.32": "certificatePolicies",
        "2.5.29.35": "authorityKeyIdentifier",
        "2.5.29.37": "extKeyUsage",
    ]

    public static func getName(_ oid: String) -> String {
        registry[oid] ?? oid
    }
}
