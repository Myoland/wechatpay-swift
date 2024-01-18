//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/5/28.
//

import Foundation

extension WechatPay.H5API {
    public struct PrepayRequest: Codable {
        public struct Amount: Codable {
            public let total: Int64
            
            
            public init(total: Int64) {
                self.total = total
            }
        }
        
        public struct SceneInfo: Codable {
            public struct H5Info: Codable {
                public let type: String
                
                public init(type: String) {
                    self.type = type
                }
            }
            
            public let payerClientIp: String
            public let h5Info: H5Info
            
            private enum CodingKeys: String, CodingKey {
                case payerClientIp = "payer_client_ip"
                case h5Info = "h5_info"
            }
            
            public init(payerClientIp: String, h5Info: H5Info) {
                self.payerClientIp = payerClientIp
                self.h5Info = h5Info
            }
        }
        
        public let mchid: String
        public let description: String
        public let outTradeNo: String
        public let notifyURL: String
        public let amount: Amount
        public let appid: String
        public let sceneInfo: SceneInfo
        
        private enum CodingKeys: String, CodingKey {
            case mchid
            case description
            case outTradeNo = "out_trade_no"
            case notifyURL = "notify_url"
            case amount
            case appid
            case sceneInfo = "scene_info"
        }
        
        public init(mchid: String,
                    description: String,
                    outTradeNo: String,
                    notifyURL: String,
                    amount: Amount,
                    appid: String,
                    sceneInfo: SceneInfo) {
            
            self.mchid = mchid
            self.description = description
            self.outTradeNo = outTradeNo
            self.notifyURL = notifyURL
            self.amount = amount
            self.appid = appid
            self.sceneInfo = sceneInfo
        }
    }
    
}
