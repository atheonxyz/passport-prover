import Foundation
import Security

public struct CscaEntry {
    public let publicKey: Data
    public let subject: String
    public let serial: String
}

public enum CscaRegistry {

    public static func load(path: String) throws -> [String: [CscaEntry]] {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PassportError.dataNotFound("Invalid CSCA registry JSON")
        }

        var registry: [String: [CscaEntry]] = [:]
        for (country, entriesAny) in json {
            guard let entries = entriesAny as? [[String: Any]] else { continue }
            var cscaList: [CscaEntry] = []
            for entry in entries {
                guard let pubKeyB64 = entry["public_key"] as? String,
                      let pubKeyBytes = Data(base64Encoded: pubKeyB64) else { continue }
                cscaList.append(CscaEntry(
                    publicKey: pubKeyBytes,
                    subject: entry["subject"] as? String ?? "",
                    serial: entry["serial"] as? String ?? ""
                ))
            }
            registry[country] = cscaList
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

    /// Verify RSA SHA256 signature using Security.framework.
    private static func verifyRSASignature(publicKeyDER: Data, data: Data, signature: Data) throws -> Bool {
        // Create SecKey from SubjectPublicKeyInfo DER
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
