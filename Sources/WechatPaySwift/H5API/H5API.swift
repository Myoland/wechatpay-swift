//
//  H5API.swift
//  API: https://pay.weixin.qq.com/doc/v3/merchant/4012791837
//
//  Created by kevinzhow on 2022/5/28.
//

import Foundation

typealias Order = [String: Any]

extension WechatPay {
    
    public struct H5API {
        public let wechatPay: WechatPay
        
        public init(wechatPay: WechatPay) {
            self.wechatPay = wechatPay
        }
        
        /// 预下单
        public func prepayWithRequestPayment(request: WechatPay.H5API.PrepayRequest) async throws -> OrderResponse {
        
            let entry = WechatPayAPIEntry.h5Order
            
            let response: OrderResponse = try await wechatPay.client.request(
                "\(entry.absolutePath)",
                method: entry.method,
                data: request
            )
            
            return response
        }
        
        /// 通过 OutTradeNo 查询订单
        public func queryTransactionWithTradeNo(_ tradeNo: String) async throws -> WechatPay.H5API.Transaction {
            
            let entry = WechatPayAPIEntry.transactionWithTradeNo
            
            let response: WechatPay.H5API.Transaction = try await wechatPay.client.request(
                "\(entry.absolutePath)/\(tradeNo)?mchid=\(self.wechatPay.mchid)",
                method: entry.method,
                decoder: self.wechatPay.decoder
            )
            
            return response
        }
        
        // 通过微信支付订单号查询订单
        public func queryTransactionWithWechatTransactionID(_ transactionID: String) async throws -> WechatPay.H5API.Transaction {
            
            let entry = WechatPayAPIEntry.transactionWithWechatTransactionID
            
            let response: WechatPay.H5API.Transaction = try await wechatPay.client.request(
                "\(entry.absolutePath)/\(transactionID)?mchid=\(self.wechatPay.mchid)",
                method: entry.method,
                decoder: self.wechatPay.decoder
            )
            
            return response
        }
        
        public func decodeNotification<T: Decodable>(_ notification: WechatPay.H5API.PayNotification) throws -> T {
            
            let json = try self.wechatPay.decodeCiphertext(ciphertext: notification.resource.ciphertext, nonce: notification.resource.nonce, tag: notification.resource.associatedData)
            
            return try self.wechatPay.decoder.decode(T.self, from: json.data(using: .utf8)!)
        }
    }
}
