//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/6/5.
//

import Foundation

extension WechatPay.H5API.PayNotification {
    public struct RefundTransaction: Codable {
        public struct Amount: Codable {
            public let total: Int
            public let refund: Int
            public let payerTotal: Int
            public let payerRefund: Int
            
            private enum CodingKeys: String, CodingKey {
                case total
                case refund
                case payerTotal = "payer_total"
                case payerRefund = "payer_refund"
            }
        }
        
        public enum RefundStatus: String, Codable {
            case success = "SUCCESS"
            case close = "CLOSE"
            case abnormal = "ABNORMAL"
        }
        
        public let mchid: String
        public let transactionID: String
        public let outTradeNo: String
        public let refundID: String
        public let outRefundNo: String
        public let refundStatus: RefundStatus
        public let successTime: Date?
        public let userReceivedAccount: String
        public let amount: Amount
        
        private enum CodingKeys: String, CodingKey {
            case mchid
            case transactionID = "transaction_id"
            case outTradeNo = "out_trade_no"
            case refundID = "refund_id"
            case outRefundNo = "out_refund_no"
            case refundStatus = "refund_status"
            case successTime = "success_time"
            case userReceivedAccount = "user_received_account"
            case amount
        }
    }
    
}
