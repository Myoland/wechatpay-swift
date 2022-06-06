//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/6/4.
//

import Foundation

extension WechatPay.H5API {
    public struct Transaction: Codable {
        public struct Amount: Codable {
            public let payerTotal: Int
            public let total: Int
            public let currency: String
            public let payerCurrency: String
            
            private enum CodingKeys: String, CodingKey {
                case payerTotal = "payer_total"
                case total
                case currency
                case payerCurrency = "payer_currency"
            }
        }
        
        public struct PromotionDetail: Codable {
            public struct GoodsDetail: Codable {
                public let goodsRemark: String?
                public let quantity: Int
                public let discountAmount: Int
                public let goodsID: String
                public let unitPrice: Int
                
                private enum CodingKeys: String, CodingKey {
                    case goodsRemark = "goods_remark"
                    case quantity
                    case discountAmount = "discount_amount"
                    case goodsID = "goods_id"
                    case unitPrice = "unit_price"
                }
            }
            
            public let amount: Int
            public let wechatpayContribute: Int?
            public let couponID: String
            public let scope: String?
            public let merchantContribute: Int?
            public let name: String?
            public let otherContribute: Int?
            public let currency: String?
            public let stockID: String?
            public let goodsDetail: [GoodsDetail]?
            
            private enum CodingKeys: String, CodingKey {
                case amount
                case wechatpayContribute = "wechatpay_contribute"
                case couponID = "coupon_id"
                case scope
                case merchantContribute = "merchant_contribute"
                case name
                case otherContribute = "other_contribute"
                case currency
                case stockID = "stock_id"
                case goodsDetail = "goods_detail"
            }
        }
        
        public struct Payer: Codable {
            public let openid: String
        }
        
        public struct SceneInfo: Codable {
            public let deviceID: String?
            
            private enum CodingKeys: String, CodingKey {
                case deviceID = "device_id"
            }
        }
        
        public enum TradeState: String, Codable {
            case success = "SUCCESS"
            case refund = "REFUND"
            case notpay = "NOTPAY"
            case closed = "CLOSED"
            case revoked = "REVOKED"
            case userPaying = "USERPAYING"
            case payError = "PAYERROR"
        }
        
        public let transactionID: String
        public let amount: Amount
        public let mchid: String
        public let tradeState: TradeState
        public let bankType: String
        public let promotionDetail: [PromotionDetail]?
        public let successTime: Date?
        public let payer: Payer
        public let outTradeNo: String
        public let appid: String
        public let tradeStateDesc: String
        public let tradeType: String
        public let attach: String?
        public let sceneInfo: SceneInfo?
        
        private enum CodingKeys: String, CodingKey {
            case transactionID = "transaction_id"
            case amount
            case mchid
            case tradeState = "trade_state"
            case bankType = "bank_type"
            case promotionDetail = "promotion_detail"
            case successTime = "success_time"
            case payer
            case outTradeNo = "out_trade_no"
            case appid
            case tradeStateDesc = "trade_state_desc"
            case tradeType = "trade_type"
            case attach
            case sceneInfo = "scene_info"
        }
    }
}
