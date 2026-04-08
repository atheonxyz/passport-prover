import Foundation
import Security

// MARK: - CSCA Entry

public struct CscaEntry: Sendable {
    public let publicKey: Data
    public let subject: String
    public let serial: String
}

// MARK: - CSCA Registry

public enum CscaRegistry {

    /// JSON shape for a single CSCA entry on disk.
    private struct EntryDTO: Decodable {
        let publicKey: String
        let subject: String?
        let serial: String?

        enum CodingKeys: String, CodingKey {
            case publicKey = "public_key"
            case subject
            case serial
        }
    }

    public static func load(path: String) throws -> [String: [CscaEntry]] {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)

        let decoded = try JSONDecoder().decode([String: [EntryDTO]].self, from: data)

        var registry: [String: [CscaEntry]] = [:]
        for (country, entries) in decoded {
            registry[country] = entries.compactMap { entry in
                guard let pubKeyBytes = Data(base64Encoded: entry.publicKey) else { return nil }
                return CscaEntry(
                    publicKey: pubKeyBytes,
                    subject: entry.subject ?? "",
                    serial: entry.serial ?? ""
                )
            }
        }
        return registry
    }

    public static func findMatchingKey(
        registry: [String: [CscaEntry]],
        country: String,
        dg1: Data,
        sod: SOD
    ) throws -> Data {
        guard let entries = registry[country] else {
            throw PassportError.dataNotFound("No CSCA entries for country: \(country)")
        }

        let tbsBytes = sod.certificate.tbs.bytes
        let cscaSignatureBytes = sod.certificate.signature

        var errors: [String] = []
        for entry in entries {
            do {
                if try verifyRSASignature(publicKeyDER: entry.publicKey, data: tbsBytes, signature: cscaSignatureBytes) {
                    print("  Matched CSCA key: serial=\(entry.serial)")
                    return entry.publicKey
                } else {
                    errors.append("serial=\(entry.serial): signature mismatch")
                }
            } catch {
                errors.append("serial=\(entry.serial): \(error.localizedDescription)")
            }
        }

        throw PassportError.dataNotFound(
            "No matching CSCA key found for \(country). Tried \(entries.count) keys:\n  " +
            errors.joined(separator: "\n  ")
        )
    }

    // MARK: - RSA Verification

    /// Verify RSA-SHA256 signature using Security.framework.
    private static func verifyRSASignature(publicKeyDER: Data, data: Data, signature: Data) throws -> Bool {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(publicKeyDER as CFData, attributes as CFDictionary, &error) else {
            if let err = error?.takeRetainedValue() {
                throw PassportError.dataNotFound("Failed to create SecKey: \(err)")
            }
            throw PassportError.dataNotFound("Failed to create SecKey")
        }

        let algorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(secKey, .verify, algorithm) else {
            throw PassportError.unsupportedSignatureAlgorithm("RSA SHA256 not supported by key")
        }

        return SecKeyVerifySignature(secKey, algorithm, data as CFData, signature as CFData, &error)
    }
}
