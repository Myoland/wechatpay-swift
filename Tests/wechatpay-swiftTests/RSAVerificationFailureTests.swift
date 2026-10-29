import XCTest
import Foundation
import JWTKit
@testable import WechatPaySwift

// Isolated offline regression using synthetic certificate and signing material only.
final class RSAVerificationFailureTests: XCTestCase {
    private func fixture(_ name: String) throws -> String {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "pem", subdirectory: "Fixtures"))
        return try String(contentsOf: url, encoding: .utf8)
    }

    private func sign(_ message: String) throws -> String {
        let key = try RSAKey.private(pem: fixture("test-verify-platform.key"))
        return Data(try JWTSigner.rs256(key: key).algorithm.sign(Data(message.utf8))).base64EncodedString()
    }

    func testMalformedBase64ReturnsFalseWithValidSyntheticCertificate() throws {
        let cert = try fixture("test-verify-platform")
        _ = try RSAKey.certificate(pem: cert)
        for signature in ["not-base64", "%%%"] {
            XCTAssertNil(Data(base64Encoded: signature))
            XCTAssertFalse(RSASigner.verify(signature: signature, message: "offline", with: cert))
        }
    }

    func testMalformedCertificateReturnsFalseWithDecodableSignature() throws {
        let signature = Data([0]).base64EncodedString()
        XCTAssertNotNil(Data(base64Encoded: signature))
        for cert in ["", "not a certificate", "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"] {
            XCTAssertThrowsError(try RSAKey.certificate(pem: cert))
            XCTAssertFalse(RSASigner.verify(signature: signature, message: "offline", with: cert))
        }
    }

    func testValidSyntheticSignatureStillVerifies() throws {
        let message = "1700000000\noffline-nonce\n{\"id\":\"synthetic\"}\n"
        XCTAssertTrue(RSASigner.verify(signature: try sign(message), message: message, with: try fixture("test-verify-platform")))
    }

    func testTamperedMessageDoesNotVerify() throws {
        let message = "offline-original"
        XCTAssertFalse(RSASigner.verify(signature: try sign(message), message: message + "-changed", with: try fixture("test-verify-platform")))
    }

    func testEmptyAndWrongLengthSignaturesReturnFalse() throws {
        let cert = try fixture("test-verify-platform")
        for signature in ["", Data([0]).base64EncodedString()] {
            XCTAssertNotNil(Data(base64Encoded: signature))
            XCTAssertFalse(RSASigner.verify(signature: signature, message: "offline", with: cert))
        }
    }

    func testPublicValidatorKeepsCanonicalMessageAndRejectsMalformedSignature() throws {
        let timestamp = "1700000000", nonce = "offline-nonce", body = "{\"id\":\"synthetic\"}"
        let validator = WechatPaySignatureValidator(wxCertContent: try fixture("test-verify-platform"))
        let signature = try sign("\(timestamp)\n\(nonce)\n\(body)\n")
        XCTAssertTrue(validator.verify(timestamp: timestamp, nonce: nonce, body: body, signature: signature))
        XCTAssertFalse(validator.verify(timestamp: timestamp, nonce: nonce, body: body, signature: "not-base64"))
    }
}
