import XCTest
import Foundation
import Crypto
import NIOCore
import NIOHTTP1
@testable import WechatPaySwift

/// Offline: injected transport, published synthetic fixture keys, fixed clock. No merchant API.
final class RefundAPITests: XCTestCase {
    let apiKey = "0123456789abcdef0123456789abcdef"
    let merchantID = "1900000001"

    final class FakeTransport: WechatPayTransport, @unchecked Sendable {
        private let lock = NSLock()
        private var _requests: [WechatPayTransportRequest] = []
        var handler: @Sendable (WechatPayTransportRequest) throws -> WechatPayTransportResponse

        init(handler: @escaping @Sendable (WechatPayTransportRequest) throws -> WechatPayTransportResponse) {
            self.handler = handler
        }
        var requests: [WechatPayTransportRequest] { lock.lock(); defer { lock.unlock() }; return _requests }
        func execute(_ request: WechatPayTransportRequest, timeout: TimeAmount) async throws -> WechatPayTransportResponse {
            lock.lock(); _requests.append(request); lock.unlock()
            return try handler(request)
        }
    }

    struct TransportDown: Error {}

    func fixture(_ name: String) throws -> String {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "pem", subdirectory: "Fixtures"))
        return try String(contentsOf: url)
    }
    func certificate(_ name: String) throws -> WechatPayPlatformCertificate {
        try WechatPayPlatformCertificate(pem: fixture("platform-" + name))
    }
    func now() throws -> Date { try certificate("a").notValidBefore.addingTimeInterval(3600) }

    func signedResponse(_ body: String, status: Int = 200, key: String = "a", serial: String? = nil) throws -> WechatPayTransportResponse {
        let timestamp = String(Int64(try now().timeIntervalSince1970))
        let nonce = "response-nonce"
        let signature = try XCTUnwrap(RSASigner.sign(text: "\(timestamp)\n\(nonce)\n\(body)\n",
                                                     privateKeyPem: fixture("platform-" + key + ".key")))
        let headers: HTTPHeaders = ["Wechatpay-Serial": try serial ?? certificate("a").serialNumber,
                                    "Wechatpay-Timestamp": timestamp, "Wechatpay-Nonce": nonce,
                                    "Wechatpay-Signature": signature]
        return WechatPayTransportResponse(status: status, headers: headers, body: Data(body.utf8))
    }

    func client(_ transport: FakeTransport) throws -> WechatPay {
        let fixed = try now()
        let store = try WechatPayPlatformCertificateStore(certificates: [certificate("a")], clock: { fixed })
        // platform-a.key doubles as the synthetic merchant signing key here.
        return try WechatPay(apiV3Secret: apiKey, certificateContent: fixture("platform-a.key"), mchid: merchantID,
                             serialNo: "MERCHANT-SERIAL-TEST", certificateProvider: store,
                             transport: transport, clock: { fixed })
    }

    func refundJSON(status: String = "PROCESSING", refund: Int64 = 100, outRefundNo: String = "rfa_test_0001") -> String {
        """
        {"amount":{"currency":"CNY","discount_refund":0,"payer_refund":\(refund),"payer_total":100,"refund":\(refund),"settlement_refund":\(refund),"settlement_total":100,"total":100},"channel":"ORIGINAL","create_time":"2026-10-29T10:00:00+08:00","funds_account":"AVAILABLE","out_refund_no":"\(outRefundNo)","out_trade_no":"ORDER-1","refund_id":"50000000382019052709732678859","status":"\(status)","transaction_id":"4200000000000000000000000001","user_received_account":"synthetic"}
        """
    }

    func request(outRefundNo: String = "rfa_test_0001") -> WechatPay.RefundAPI.CreateRefundRequest {
        .init(transactionID: "4200000000000000000000000001", outRefundNo: outRefundNo, reason: "synthetic test",
              notifyURL: "https://pay-approve.example.test/api/v1/refund-approval/callbacks/wechat",
              amount: .init(refund: 100, total: 100, currency: "CNY"))
    }

    func testCreateSignsRequestAndVerifiesResponse() async throws {
        let body = refundJSON()
        let response = try signedResponse(body)
        let transport = FakeTransport { _ in response }
        let refund = try await WechatPay.RefundAPI(wechatPay: client(transport)).create(request())
        XCTAssertEqual(refund.status, .processing)
        XCTAssertEqual(refund.outRefundNo, "rfa_test_0001")
        XCTAssertEqual(refund.amount.refund, 100)
        XCTAssertEqual(refund.amount.currency, "CNY")

        let sent = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(transport.requests.count, 1)
        XCTAssertEqual(sent.method, .POST)
        XCTAssertEqual(sent.url, "https://api.mch.weixin.qq.com/v3/refund/domestic/refunds")
        XCTAssertEqual(sent.body, try request().encodedBody())
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(sent.body)) as? [String: Any])
        XCTAssertEqual(Set(json.keys), ["transaction_id", "out_refund_no", "reason", "notify_url", "amount"])
        XCTAssertEqual(sent.headers.first(name: "Content-Type"), "application/json")

        // The merchant Authorization signature covers method, path, timestamp, nonce and exact body.
        let authorization = try XCTUnwrap(sent.headers.first(name: "Authorization"))
        XCTAssertTrue(authorization.hasPrefix("WECHATPAY2-SHA256-RSA2048 "))
        func field(_ name: String) throws -> String {
            let marker = name + "=\""
            let start = try XCTUnwrap(authorization.range(of: marker)).upperBound
            let end = try XCTUnwrap(authorization[start...].firstIndex(of: "\""))
            return String(authorization[start..<end])
        }
        XCTAssertEqual(try field("mchid"), merchantID)
        XCTAssertEqual(try field("serial_no"), "MERCHANT-SERIAL-TEST")
        let message = "POST\n/v3/refund/domestic/refunds\n\(try field("timestamp"))\n\(try field("nonce_str"))\n\(String(decoding: try XCTUnwrap(sent.body), as: UTF8.self))\n"
        XCTAssertTrue(RSASigner.verify(signature: try field("signature"), message: message, with: try fixture("platform-a")))
    }

    func testQueryUsesSameOutRefundNoPathWithoutBody() async throws {
        let response = try signedResponse(refundJSON(status: "SUCCESS"))
        let transport = FakeTransport { _ in response }
        let refund = try await WechatPay.RefundAPI(wechatPay: client(transport)).query(outRefundNo: "rfa_test_0001")
        XCTAssertEqual(refund.status, .success)
        let sent = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(sent.method, .GET)
        XCTAssertEqual(sent.url, "https://api.mch.weixin.qq.com/v3/refund/domestic/refunds/rfa_test_0001")
        XCTAssertNil(sent.body)
    }

    func testForgedTamperedOrUnsignedResponsesAreRejected() async throws {
        let body = refundJSON(status: "SUCCESS")
        let wrongKey = try signedResponse(body, key: "b")
        var tampered = try signedResponse(body)
        tampered = WechatPayTransportResponse(status: 200, headers: tampered.headers,
                                              body: Data(body.replacingOccurrences(of: "\"refund\":100", with: "\"refund\":1").utf8))
        let unsigned = WechatPayTransportResponse(status: 200, headers: [:], body: Data(body.utf8))
        for response in [wrongKey, tampered, unsigned] {
            let transport = FakeTransport { _ in response }
            do {
                _ = try await WechatPay.RefundAPI(wechatPay: client(transport)).query(outRefundNo: "rfa_test_0001")
                XCTFail("unverified response accepted")
            } catch let error as WechatPayRefundError {
                XCTAssertEqual(error, .invalidSignature)
            }
        }
    }

    func testNon200ExposesOnlyStatusAndSanitisedCode() async throws {
        let cases: [(String, String?)] = [
            (#"{"code":"RESOURCE_NOT_EXISTS","message":"merchant detail must not leak"}"#, "RESOURCE_NOT_EXISTS"),
            (#"{"code":"lowercase<script>","message":"x"}"#, nil),
            ("not json", nil),
        ]
        for (body, code) in cases {
            let transport = FakeTransport { _ in WechatPayTransportResponse(status: 404, headers: [:], body: Data(body.utf8)) }
            do {
                _ = try await WechatPay.RefundAPI(wechatPay: client(transport)).query(outRefundNo: "rfa_test_0001")
                XCTFail("non-200 accepted")
            } catch let error as WechatPayRefundError {
                XCTAssertEqual(error, .unexpectedStatus(404, code: code))
            }
        }
    }

    func testTransportFailureIsReportedAsUnknownOutcome() async throws {
        let transport = FakeTransport { _ in throw TransportDown() }
        do {
            _ = try await WechatPay.RefundAPI(wechatPay: client(transport)).create(request())
            XCTFail("transport failure accepted")
        } catch let error as WechatPayRefundError {
            XCTAssertEqual(error, .transportFailed)
        }
        XCTAssertEqual(transport.requests.count, 1)
    }

    func testUnknownStatusOrMissingFieldsAreInvalidResponse() async throws {
        for body in [refundJSON(status: "MAYBE"), #"{"status":"SUCCESS"}"#] {
            let response = try signedResponse(body)
            let transport = FakeTransport { _ in response }
            do {
                _ = try await WechatPay.RefundAPI(wechatPay: client(transport)).query(outRefundNo: "rfa_test_0001")
                XCTFail("malformed refund accepted")
            } catch let error as WechatPayRefundError {
                XCTAssertEqual(error, .invalidResponse)
            }
        }
    }

    func testInvalidRequestsNeverTouchTransport() async throws {
        let amount = WechatPay.RefundAPI.CreateRefundRequest.Amount(refund: 100, total: 100, currency: "CNY")
        let invalid: [WechatPay.RefundAPI.CreateRefundRequest] = [
            .init(outRefundNo: "rfa_1", amount: amount),
            .init(transactionID: "4200", outTradeNo: "ORDER-1", outRefundNo: "rfa_1", amount: amount),
            .init(transactionID: "4200", outRefundNo: "rfa|1", amount: amount),
            .init(transactionID: "4200", outRefundNo: String(repeating: "a", count: 65), amount: amount),
            .init(transactionID: "4200", outRefundNo: "rfa_1", amount: .init(refund: 101, total: 100, currency: "CNY")),
            .init(transactionID: "4200", outRefundNo: "rfa_1", amount: .init(refund: 0, total: 100, currency: "CNY")),
            .init(transactionID: "4200", outRefundNo: "rfa_1", amount: .init(refund: 100, total: 100, currency: "USD")),
            .init(transactionID: "4200", outRefundNo: "rfa_1", notifyURL: "http://insecure.example/cb", amount: amount),
            .init(transactionID: "4200", outRefundNo: "rfa_1", notifyURL: "https://x.example/cb?a=1", amount: amount),
            .init(transactionID: "4200", outRefundNo: "rfa_1", reason: String(repeating: "长", count: 81), amount: amount),
        ]
        let transport = FakeTransport { _ in XCTFail("transport called"); throw TransportDown() }
        let api = WechatPay.RefundAPI(wechatPay: try client(transport))
        for request in invalid {
            do { _ = try await api.create(request); XCTFail("invalid request sent") }
            catch let error as WechatPayRefundError { XCTAssertEqual(error, .invalidRequest) }
        }
        for number in ["", "a/b", "a b", "a?x=1", "../x"] {
            do { _ = try await api.query(outRefundNo: number); XCTFail("invalid query sent") }
            catch let error as WechatPayRefundError { XCTAssertEqual(error, .invalidRequest) }
        }
        XCTAssertEqual(transport.requests.count, 0)
    }

    func testEncodedBodyIsDeterministicAndOmitsAbsentFields() throws {
        let value = WechatPay.RefundAPI.CreateRefundRequest(
            transactionID: "4200", outRefundNo: "rfa_1", amount: .init(refund: 1, total: 2, currency: "CNY"))
        XCTAssertEqual(try value.encodedBody(), try value.encodedBody())
        XCTAssertEqual(String(decoding: try value.encodedBody(), as: UTF8.self),
                       #"{"amount":{"currency":"CNY","refund":1,"total":2},"out_refund_no":"rfa_1","transaction_id":"4200"}"#)
    }

    func notification(event: String, status: String, originalType: String = "refund", tamper: Bool = false) throws -> WechatPay.H5API.PayNotification {
        let plaintext = #"{"mchid":"1900000001","transaction_id":"4200000000000000000000000001","out_trade_no":"ORDER-1","refund_id":"50000000382019052709732678859","out_refund_no":"rfa_test_0001","refund_status":"\#(status)","success_time":"2026-10-29T10:01:00+08:00","user_received_account":"synthetic","amount":{"total":100,"refund":100,"payer_total":100,"payer_refund":100}}"#
        let nonce = "refundnonce1"
        let sealed = try AES.GCM.seal(Data(plaintext.utf8), using: SymmetricKey(data: Data(apiKey.utf8)),
                                      nonce: AES.GCM.Nonce(data: Data(nonce.utf8)), authenticating: Data("refund".utf8))
        var ciphertext = sealed.ciphertext + sealed.tag
        if tamper { ciphertext[ciphertext.startIndex] ^= 0x01 }
        let envelope: [String: Any] = [
            "id": "EV-1", "create_time": "2026-10-29T10:01:01+08:00", "resource_type": "encrypt-resource",
            "event_type": event, "summary": "synthetic",
            "resource": ["original_type": originalType, "algorithm": "AEAD_AES_256_GCM", "ciphertext": ciphertext.base64EncodedString(),
                         "associated_data": "refund", "nonce": nonce]]
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(WechatPay.H5API.PayNotification.self,
                                  from: JSONSerialization.data(withJSONObject: envelope))
    }

    func testRefundNotificationDecodesThroughExistingDecryptPath() throws {
        let api = WechatPay.RefundAPI(wechatPay: try client(FakeTransport { _ in throw TransportDown() }))
        let resource = try api.decodeNotification(notification(event: "REFUND.SUCCESS", status: "SUCCESS"))
        XCTAssertEqual(resource.refundStatus, .success)
        XCTAssertEqual(resource.outRefundNo, "rfa_test_0001")
        XCTAssertEqual(resource.amount.refund, 100)
        XCTAssertNil(resource.amount.currency)
        XCTAssertEqual(try api.decodeNotification(notification(event: "REFUND.CLOSED", status: "CLOSE")).refundStatus, .closed)

        let rejected = [
            try notification(event: "REFUND.SUCCESS", status: "CLOSE"),
            try notification(event: "REFUND.SUCCESS", status: "SUCCESS", originalType: "transaction"),
            try notification(event: "REFUND.SUCCESS", status: "SUCCESS", tamper: true),
            try notification(event: "TRANSACTION.SUCCESS", status: "SUCCESS"),
        ]
        for item in rejected {
            XCTAssertThrowsError(try api.decodeNotification(item)) {
                XCTAssertEqual($0 as? WechatPayRefundError, .invalidNotification)
            }
        }
    }

    func testExistingH5RequestPathStillVerifiesThroughTransport() async throws {
        let body = #"{"amount":{"currency":"CNY","payer_currency":"CNY","payer_total":100,"total":100},"appid":"wx0000000000000000","bank_type":"OTHERS","mchid":"1900000001","out_trade_no":"ORDER-1","payer":{"openid":"synthetic"},"success_time":"2026-10-29T10:00:00+08:00","trade_state":"SUCCESS","trade_state_desc":"ok","trade_type":"MWEB","transaction_id":"4200000000000000000000000001"}"#
        let good = try signedResponse(body)
        let transport = FakeTransport { _ in good }
        let transaction = try await WechatPay.H5API(wechatPay: client(transport)).queryTransactionWithTradeNo("ORDER-1")
        XCTAssertEqual(transaction.tradeState, .success)
        XCTAssertEqual(transport.requests.first?.url,
                       "https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/ORDER-1?mchid=1900000001")

        let forged = try signedResponse(body, key: "b")
        do {
            _ = try await WechatPay.H5API(wechatPay: client(FakeTransport { _ in forged })).queryTransactionWithTradeNo("ORDER-1")
            XCTFail("forged response accepted")
        } catch is WechatPayPlatformCertificateError {}
        do {
            _ = try await WechatPay.H5API(wechatPay: client(FakeTransport { _ in
                WechatPayTransportResponse(status: 500, headers: [:], body: Data("x".utf8)) })).queryTransactionWithTradeNo("ORDER-1")
            XCTFail("500 accepted")
        } catch WechatPay.Client.ClientError.unexpectedResponse {}
    }
}
