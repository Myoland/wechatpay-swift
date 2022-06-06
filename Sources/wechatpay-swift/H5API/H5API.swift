//
//  File.swift
//
//
//  Created by kevinzhow on 2022/5/28.
//

import Foundation
import Alamofire

typealias Order = [String: Any]

extension WechatPay {
    
    public struct H5API {
        public let wechatPay: WechatPay
        
        public init(wechatPay: WechatPay) {
            self.wechatPay = wechatPay
        }
        
        /// 预下单
        public func prepayWithRequestPayment(request: WechatPay.H5API.PrepayRequest) async throws -> DataResponse<OrderResponse, AFError> {
        
            let entry = WechatPayAPIEntry.h5Order
            
            let response = await AF.request(
                "\(entry.absolutePath)",
                method: entry.method,
                parameters: request,
                encoder: JSONParameterEncoder.default,
                interceptor: self.wechatPay.interceptor
            ).validate(wechatPay.validator.validation).serializingDecodable(OrderResponse.self).response
            
            return response
        }
        
        /// 通过 TradeNo 查询订单
        public func queryTransactionWithTradeNo(_ tradeNo: String) async throws -> DataResponse<WechatPay.H5API.Transaction, AFError> {
            
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            
            let entry = WechatPayAPIEntry.transactionWithTradeNo
            
            let response = await AF.request(
                "\(entry.absolutePath)/\(tradeNo)?mchid=\(self.wechatPay.mchid)",
                method: entry.method,
                interceptor: self.wechatPay.interceptor
            ).validate(wechatPay.validator.validation).serializingDecodable(WechatPay.H5API.Transaction.self, decoder: decoder).response
            
            return response
        }
        
        public func decodeNotification<T: Decodable>(_ notification: WechatPay.H5API.PayNotification) throws -> T {
            
            let json = try self.wechatPay.decodeCiphertext(ciphertext: notification.resource.ciphertext, nonce: notification.resource.nonce, tag: notification.resource.associatedData)
            
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            
            return try decoder.decode(T.self, from: json.data(using: .utf8)!)
        }
    }
}
