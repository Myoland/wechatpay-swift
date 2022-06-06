import XCTest
import Alamofire
import Crypto
import JWTKit
@testable import wechatpay_swift

final class wechatpaySignTests: XCTestCase {
    
    var wechatPay: WechatPay!
    
    override func setUp() async throws {
        
        wechatPay = WechatPay(
            apiV3Secret: Environment.get("API_V3_KEY") ?? "",
            certificatePath: Environment.get("MCH_CERT_PATH") ?? "",
            wxCertificatePath: Environment.get("WECHAT_PLATFORM_CERT_PATH") ?? "",
            mchid: Environment.get("MCHID") ?? "",
            serialNo: Environment.get("SERIAL_NO") ?? "")
    }
    
    func testGetCertificate() async throws {
        let certResponse = try await wechatPay.downloadCertificates()
        
        if let cert = certResponse.value?.data.first {
            let decodedCert = try wechatPay.decodeCert(cert: cert)
            XCTAssertNotNil(decodedCert)
        }
    }
    
    func testH5Order() async throws {
        
        let request = WechatPay.H5API.PrepayRequest(
            mchid: wechatPay.mchid,
            description: "Test Product",
            outTradeNo: Environment.get("TEST_OUT_TRADE_NO") ?? "",
            notifyURL: Environment.get("NOTIFY_URL") ?? "",
            amount:  WechatPay.H5API.PrepayRequest.Amount(total: 6800),
            appid: Environment.get("TEST_APPID") ?? "",
            sceneInfo:  WechatPay.H5API.PrepayRequest.SceneInfo(
                payerClientIp: "127.0.0.1",
                h5Info: WechatPay.H5API.PrepayRequest.SceneInfo.H5Info(type: "Wap")))
        
        let client = WechatPay.H5API(wechatPay: wechatPay)
        
        let h5Response = try await client.prepayWithRequestPayment(request: request)
        
        XCTAssertNotNil(h5Response.value)
    }
    
    func testQueryH5OrderRefund() async throws {

        let client = WechatPay.H5API(wechatPay: wechatPay)
        
        let h5Response = try await client.queryTransactionWithTradeNo(Environment.get("TEST_ORDER_NO") ?? "")
        
        XCTAssertNotNil(h5Response.value)
    }
    
    func testQueryH5OrderSuccess() async throws {

        let client = WechatPay.H5API(wechatPay: wechatPay)
        
        let h5Response = try await client.queryTransactionWithTradeNo(Environment.get("TEST_ORDER_NO_SUCCESS") ?? "")
        
        XCTAssertNotNil(h5Response.value)
    }
}
