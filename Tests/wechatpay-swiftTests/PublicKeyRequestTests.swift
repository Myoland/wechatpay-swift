import XCTest
import Foundation
import NIOCore
import NIOHTTP1
@testable import WechatPaySwift

/// Offline request/response migration contract, using only published synthetic fixtures.
final class PublicKeyRequestTests: XCTestCase {
    actor Capture: WechatPayTransport {
        let response: WechatPayTransportResponse
        private(set) var requests: [WechatPayTransportRequest] = []
        init(_ response: WechatPayTransportResponse) { self.response = response }
        func execute(_ request: WechatPayTransportRequest, timeout: TimeAmount) async throws -> WechatPayTransportResponse {
            requests.append(request)
            return response
        }
    }

    func fixture(_ name: String) throws -> String {
        let path = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "pem", subdirectory: "Fixtures"))
        return try String(contentsOf: path)
    }
    func certificate() throws -> WechatPayPlatformCertificate {
        try WechatPayPlatformCertificate(pem: fixture("platform-a"))
    }
    func key(_ name: String = "a", id: String = "PUB_KEY_ID_OFFLINE_A") throws -> TrustedWechatPublicKey {
        try TrustedWechatPublicKey(id: id, pem: fixture("platform-" + name + ".public"))
    }
    func now() throws -> Date { try certificate().notValidBefore.addingTimeInterval(3600) }
    func response(serial: String, signingKey: String = "a") throws -> WechatPayTransportResponse {
        let body = #"{"out_refund_no":"refund-offline","out_trade_no":"order-offline","transaction_id":"tx-offline","refund_id":"refund-provider-offline","status":"SUCCESS","amount":{"refund":100,"total":100,"payer_refund":100,"payer_total":100,"settlement_refund":100,"settlement_total":100,"discount_refund":0,"currency":"CNY"},"channel":"ORIGINAL","create_time":"2026-10-29T10:00:00+08:00","funds_account":"AVAILABLE","user_received_account":"synthetic"}"#
        let timestamp = String(Int64(try now().timeIntervalSince1970))
        let signature = try XCTUnwrap(RSASigner.sign(text: "\(timestamp)\nnonce\n\(body)\n", privateKeyPem: fixture("platform-" + signingKey + ".key")))
        return .init(status: 200, headers: ["Wechatpay-Serial": serial, "Wechatpay-Timestamp": timestamp,
                                          "Wechatpay-Nonce": "nonce", "Wechatpay-Signature": signature], body: Data(body.utf8))
    }
    func client(_ transport: Capture, certificates: [WechatPayPlatformCertificate] = [],
                trusted: [TrustedWechatPublicKey], selected: TrustedWechatPublicKey? = nil) throws -> WechatPay {
        let fixed = try now()
        let provider = try WechatPayPlatformCertificateStore(certificates: certificates, clock: { fixed }, publicKeys: trusted)
        return try WechatPay(apiV3Secret: "0123456789abcdef0123456789abcdef", certificateContent: fixture("platform-a.key"),
                             mchid: "merchant-offline", serialNo: "MERCHANT-SERIAL-OFFLINE", certificateProvider: provider,
                             transport: transport, responsePublicKey: selected, clock: { fixed })
    }

    func testPublicKeyResponseSelectionKeepsMerchantRequestSignature() async throws {
        let publicKey = try key()
        let transport = Capture(try response(serial: publicKey.id))
        let api = WechatPay.RefundAPI(wechatPay: try client(transport, trusted: [publicKey], selected: publicKey))
        let result = try await api.query(outRefundNo: "refund-offline")
        XCTAssertEqual(result.status, .success)
        let requests = await transport.requests
        let request = try XCTUnwrap(requests.first)
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(request.headers["Wechatpay-Serial"], [publicKey.id])
        let authorization = try XCTUnwrap(request.headers.first(name: "Authorization"))
        func field(_ name: String) throws -> String {
            let start = try XCTUnwrap(authorization.range(of: name + "=\"")).upperBound
            let end = try XCTUnwrap(authorization[start...].firstIndex(of: "\""))
            return String(authorization[start..<end])
        }
        XCTAssertEqual(try field("serial_no"), "MERCHANT-SERIAL-OFFLINE")
        let signed = "GET\n/v3/refund/domestic/refunds/refund-offline\n\(try field("timestamp"))\n\(try field("nonce_str"))\n\n"
        XCTAssertTrue(RSASigner.verify(signature: try field("signature"), message: signed, with: try fixture("platform-a")))
    }

    func testMigrationRetainsCertificateSignedResponses() async throws {
        let publicKey = try key("b", id: "PUB_KEY_ID_OFFLINE_B")
        let oldCertificate = try certificate()
        let transport = Capture(try response(serial: oldCertificate.serialNumber))
        let api = WechatPay.RefundAPI(wechatPay: try client(transport, certificates: [oldCertificate], trusted: [publicKey], selected: publicKey))
        let result = try await api.query(outRefundNo: "refund-offline")
        XCTAssertEqual(result.status, .success)
        let requests = await transport.requests
        XCTAssertEqual(requests.first?.headers.first(name: "Wechatpay-Serial"), publicKey.id)
    }

    func testLegacyCertificateClientDoesNotAdvertisePublicKey() async throws {
        let oldCertificate = try certificate()
        let transport = Capture(try response(serial: oldCertificate.serialNumber))
        let api = WechatPay.RefundAPI(wechatPay: try client(transport, certificates: [oldCertificate], trusted: []))
        _ = try await api.query(outRefundNo: "refund-offline")
        let requests = await transport.requests
        XCTAssertNil(requests.first?.headers.first(name: "Wechatpay-Serial"))
    }

    func testUnknownOrForgedPublicKeyResponsesAreRejected() async throws {
        let publicKey = try key()
        for response in [try response(serial: "PUB_KEY_ID_NOT_TRUSTED"), try response(serial: publicKey.id, signingKey: "b")] {
            let transport = Capture(response)
            let api = WechatPay.RefundAPI(wechatPay: try client(transport, trusted: [publicKey], selected: publicKey))
            do { _ = try await api.query(outRefundNo: "refund-offline"); XCTFail("unverified response accepted") }
            catch let error as WechatPayRefundError { XCTAssertEqual(error, .invalidSignature) }
        }
    }

    func testMissingOrConflictingSelectedTrustFailsBeforeTransport() async throws {
        let publicKey = try key()
        let conflicting = try key("b", id: publicKey.id)
        for trusted in [[], [conflicting]] as [[TrustedWechatPublicKey]] {
            let transport = Capture(try response(serial: publicKey.id))
            let api = WechatPay.RefundAPI(wechatPay: try client(transport, trusted: trusted, selected: publicKey))
            do { _ = try await api.query(outRefundNo: "refund-offline"); XCTFail("untrusted response key selected") }
            catch { }
            let requests = await transport.requests
            XCTAssertTrue(requests.isEmpty)
        }
    }
}
