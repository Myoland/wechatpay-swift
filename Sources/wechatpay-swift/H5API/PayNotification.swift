//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/6/4.
//

import Foundation

extension WechatPay.H5API {
    public struct PayNotification: Codable {
        
        public enum EventType: String, Codable {
            case refundSuccess = "REFUND.SUCCESS"
            case refundAbnormal = "REFUND.ABNORMAL"
            case refundClosed = "REFUND.CLOSED"
            case transactionSuccess = "TRANSACTION.SUCCESS"
        }
        
        public struct Resource: Codable {
            public let originalType: String
            public let algorithm: String
            public let ciphertext: String
            public let associatedData: String
            public let nonce: String
            
            private enum CodingKeys: String, CodingKey {
                case originalType = "original_type"
                case algorithm
                case ciphertext
                case associatedData = "associated_data"
                case nonce
            }
        }
        
        public let id: String
        public let createTime: Date
        public let resourceType: String
        public let eventType: EventType
        public let summary: String
        public let resource: Resource
        
        private enum CodingKeys: String, CodingKey {
            case id
            case createTime = "create_time"
            case resourceType = "resource_type"
            case eventType = "event_type"
            case summary
            case resource
        }
    }
    
}

extension WechatPay.H5API.PayNotification {
    public struct Response: Codable {
        public let code: String
        public let message: String
        
        public init(code: String, message: String) {
            self.code = code
            self.message = message
        }
    }
}
