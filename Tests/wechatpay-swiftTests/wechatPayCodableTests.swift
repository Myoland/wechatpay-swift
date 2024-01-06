import XCTest
import Crypto
import JWTKit
@testable import WechatPaySwift

final class wechatpayCodableTests: XCTestCase {
    
    func testDecodeRefundNotification() async throws {
        let json = """
{
    "id":"EV-2018022511223320873",
    "create_time":"2018-06-08T10:34:56+08:00",
    "resource_type":"encrypt-resource",
    "event_type":"REFUND.SUCCESS",
    "summary":"退款成功",
    "resource" : {
        "algorithm":"AEAD_AES_256_GCM",
        "original_type": "refund",
        "ciphertext": "...",
        "nonce": "...",
        "associated_data": ""
    }
}
"""
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        let notification = try decoder.decode( WechatPay.H5API.PayNotification.self, from: json.data(using: .utf8)!)
        
        XCTAssertEqual(notification.eventType, WechatPay.H5API.PayNotification.EventType.refundSuccess)
    }
    
    func testDecodeTransaction() async throws {
        let json = """

{
    "transaction_id":"1217752501201407033233368018",
    "amount":{
        "payer_total":100,
        "total":100,
        "currency":"CNY",
        "payer_currency":"CNY"
    },
    "mchid":"1230000109",
    "trade_state":"SUCCESS",
    "bank_type":"CMC",
    "promotion_detail":[
        {
            "amount":100,
            "wechatpay_contribute":0,
            "coupon_id":"109519",
            "scope":"GLOBAL",
            "merchant_contribute":0,
            "name":"单品惠-6",
            "other_contribute":0,
            "currency":"CNY",
            "stock_id":"931386",
            "goods_detail":[
                {
                    "goods_remark":"商品备注信息",
                    "quantity":1,
                    "discount_amount":1,
                    "goods_id":"M1006",
                    "unit_price":100
                },
                {
                    "goods_remark":"商品备注信息",
                    "quantity":1,
                    "discount_amount":1,
                    "goods_id":"M1006",
                    "unit_price":100
                }
            ]
        },
        {
            "amount":100,
            "wechatpay_contribute":0,
            "coupon_id":"109519",
            "scope":"GLOBAL",
            "merchant_contribute":0,
            "name":"单品惠-6",
            "other_contribute":0,
            "currency":"CNY",
            "stock_id":"931386",
            "goods_detail":[
                {
                    "goods_remark":"商品备注信息",
                    "quantity":1,
                    "discount_amount":1,
                    "goods_id":"M1006",
                    "unit_price":100
                },
                {
                    "goods_remark":"商品备注信息",
                    "quantity":1,
                    "discount_amount":1,
                    "goods_id":"M1006",
                    "unit_price":100
                }
            ]
        }
    ],
    "success_time":"2018-06-08T10:34:56+08:00",
    "payer":{
        "openid":"oUpF8uMuAJO_M2pxb1Q9zNjWeS6o"
    },
    "out_trade_no":"1217752501201407033233368018",
    "appid":"wxd678efh567hg6787",
    "trade_state_desc":"支付成功",
    "trade_type":"MICROPAY",
    "attach":"自定义数据",
    "scene_info":{
        "device_id":"013467007045764"
    }
}
"""
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        let transaction = try decoder.decode( WechatPay.H5API.Transaction.self, from: json.data(using: .utf8)!)
        
        XCTAssertEqual(transaction.tradeState, .success)
    }
    
    func testDecodeRefundTransaction() async throws {
        let json = """
{
    "mchid": "1900000100",
    "transaction_id": "1008450740201411110005820873",
    "out_trade_no": "20150806125346",
    "refund_id": "50200207182018070300011301001",
    "out_refund_no": "7752501201407033233368018",
    "refund_status": "SUCCESS",
    "success_time": "2018-06-08T10:34:56+08:00",
    "user_received_account": "招商银行信用卡0403",
    "amount" : {
        "total": 999,
        "refund": 999,
        "payer_total": 999,
        "payer_refund": 999
    }
}
"""
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        let transaction = try decoder.decode( WechatPay.H5API.PayNotification.RefundTransaction.self, from: json.data(using: .utf8)!)
        
        XCTAssertEqual(transaction.refundStatus, .success)
    }

}
