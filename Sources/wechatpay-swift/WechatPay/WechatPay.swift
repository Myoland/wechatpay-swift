//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/5/27.
//

import Foundation
import Crypto
import NIOHTTP1
import AsyncHTTPClient

enum WechatPayAPIEntry {
    case downloadCertificates
    case h5Order
    case transactionWithTradeNo
    
    static let host = "https://api.mch.weixin.qq.com/v3"
    
    var path: String {
        switch self {
        case .downloadCertificates:
            return "/certificates"
        case .h5Order:
            return "/pay/transactions/h5"
        case .transactionWithTradeNo:
            return "/pay/transactions/out-trade-no"
        }
    }
    
    var absolutePath: String {
        return WechatPayAPIEntry.host + self.path
    }
    
    var method: HTTPMethod {
        switch self {
        case .downloadCertificates:
            return .GET
        case .h5Order:
            return .POST
        case .transactionWithTradeNo:
            return .GET
        }
    }
}

public struct WechatPay {
    /// V3 密钥
    public let apiV3Secret: String
    /// 证书路径
    public let certificatePath: String
    /// 微信平台证书路径
    public let wxCertificatePath: String
    /// 商户号
    public let mchid: String
    /// 商户证书序列号
    public let serialNo: String
    
    /// 执行请求的 Client
    let client: WechatPay.Client
    
    let decoder = JSONDecoder()
    
    public init(apiV3Secret: String,
                certificatePath: String,
                wxCertificatePath: String,
                mchid: String,
                serialNo: String) {
        self.apiV3Secret = apiV3Secret
        self.certificatePath = certificatePath
        self.mchid = mchid
        self.serialNo = serialNo
        self.wxCertificatePath = wxCertificatePath
        self.decoder.dateDecodingStrategy = .iso8601
        self.client = WechatPay.Client(httpClient: HTTPClient(eventLoopGroupProvider: .singleton), requestInterceptor: WechatPayRequestInterceptor(mchid: mchid, serialNo: serialNo, certificatePath: certificatePath), validator: WechatPaySignatureValidator(wxCertPath: wxCertificatePath))
    }
}


extension WechatPay {
    func decodeCiphertext(ciphertext: String, nonce: String, tag: String) throws -> String {
        let ciphertextData = Data(base64Encoded: ciphertext)!

        let sharedKey = SymmetricKey(data: self.apiV3Secret.data(using: .utf8)!)
        
        let aNonce = try AES.GCM.Nonce(data: nonce.data(using: .utf8)!)
        
        let combinedData = aNonce + ciphertextData
        
        let box = try AES.GCM.SealedBox(combined: combinedData)
        
        let decryptedData = try AES.GCM.open(box, using: sharedKey, authenticating: tag.data(using: .utf8)!)
        
        let plaintext = String(data: decryptedData, encoding: .utf8)!
        
        return plaintext
    }
}
