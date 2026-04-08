import XCTest
@testable import PassportProverLib

final class WitnessEncoderTests: XCTestCase {

    // MARK: - Stage Witness Encoding

    func testStage1WitnessEncodesSnakeCase() throws {
        let witness = Stage1Witness(
            cscKeyNeHash: "0xabc",
            cscPubkey: ["1", "2"],
            cscPubkeyRedcParam: ["3"],
            salt: "0x1",
            country: "USA",
            tbsCertificate: ["0"],
            dscSignature: ["4", "5"],
            tbsCertificateLen: "100",
            exponent: "65537"
        )

        let json = try WitnessEncoder.encode(witness)

        // Verify snake_case keys
        XCTAssertTrue(json.contains("\"csc_key_ne_hash\""))
        XCTAssertTrue(json.contains("\"csc_pubkey\""))
        XCTAssertTrue(json.contains("\"csc_pubkey_redc_param\""))
        XCTAssertTrue(json.contains("\"tbs_certificate\""))
        XCTAssertTrue(json.contains("\"dsc_signature\""))
        XCTAssertTrue(json.contains("\"tbs_certificate_len\""))

        // Verify values are strings
        XCTAssertTrue(json.contains("\"0xabc\""))
        XCTAssertTrue(json.contains("\"65537\""))
        XCTAssertTrue(json.contains("\"USA\""))
    }

    func testStage4WitnessEncodesAllFields() throws {
        let witness = Stage4Witness(
            root: "0x0",
            sodHash: "0x1",
            dg1: ["0"],
            rDg1: "0x2",
            serviceScope: "0x0",
            serviceSubscope: "0x0",
            currentDate: "1735689600",
            leafIndex: "0",
            merklePath: ["0x0", "0x0"],
            minAgeRequired: "18",
            maxAgeRequired: "0",
            nullifierSecret: "0x0"
        )

        let json = try WitnessEncoder.encode(witness)

        XCTAssertTrue(json.contains("\"sod_hash\""))
        XCTAssertTrue(json.contains("\"r_dg1\""))
        XCTAssertTrue(json.contains("\"service_scope\""))
        XCTAssertTrue(json.contains("\"service_subscope\""))
        XCTAssertTrue(json.contains("\"current_date\""))
        XCTAssertTrue(json.contains("\"leaf_index\""))
        XCTAssertTrue(json.contains("\"merkle_path\""))
        XCTAssertTrue(json.contains("\"min_age_required\""))
        XCTAssertTrue(json.contains("\"max_age_required\""))
        XCTAssertTrue(json.contains("\"nullifier_secret\""))
    }

    func testEncodedJSONIsValidJSON() throws {
        let witness = Stage1Witness(
            cscKeyNeHash: "0x0",
            cscPubkey: [],
            cscPubkeyRedcParam: [],
            salt: "0x1",
            country: "X",
            tbsCertificate: [],
            dscSignature: [],
            tbsCertificateLen: "0",
            exponent: "3"
        )

        let json = try WitnessEncoder.encode(witness)
        let data = json.data(using: .utf8)!

        // Should parse as valid JSON
        let parsed = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?["salt"] as? String, "0x1")
        XCTAssertEqual(parsed?["country"] as? String, "X")
    }
}
