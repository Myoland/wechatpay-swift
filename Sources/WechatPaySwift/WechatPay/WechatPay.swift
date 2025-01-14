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
    case transactionWithWechatTransactionID
    
    static let host = "https://api.mch.weixin.qq.com/v3"
    
    var path: String {
        switch self {
        case .downloadCertificates:
            return "/certificates"
        case .h5Order:
            return "/pay/transactions/h5"
        case .transactionWithTradeNo:
            return "/pay/transactions/out-trade-no"
        case .transactionWithWechatTransactionID:
            return "/pay/transactions/id"
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
        case .transactionWithWechatTransactionID:
            return .GET
        }
    }
}

public class WechatPay {
    /// V3 Secret
    public let apiV3Secret: String
    /// PEM of certificate
    public let certificateContent: String
    /// PEM of Wechat Platform certificate
    public let wxCertificateContent: String
    /// mchid
    public let mchid: String
    /// merchant certificate serial number
    public let serialNo: String
    
    /// 执行请求的 Client
    let client: WechatPay.Client
    
    let decoder = JSONDecoder()
    
    public init(apiV3Secret: String,
                certificateContent: String,
                wxCertificateContent: String,
                mchid: String,
                serialNo: String) throws {
        self.apiV3Secret = apiV3Secret
        self.certificateContent = certificateContent
        self.mchid = mchid
        self.serialNo = serialNo
        self.wxCertificateContent = wxCertificateContent
        self.decoder.dateDecodingStrategy = .iso8601
        self.client = WechatPay.Client(httpClient: HTTPClient(eventLoopGroupProvider: .singleton), requestInterceptor: WechatPayRequestInterceptor(mchid: mchid, serialNo: serialNo, certificateContent: certificateContent), validator: WechatPaySignatureValidator(wxCertContent: wxCertificateContent))
    }
    
    public convenience init(apiV3Secret: String,
                certificatePath: String,
                wxCertificatePath: String,
                mchid: String,
                serialNo: String) throws {
       
        let certContent = try String(contentsOf: URL(fileURLWithPath: certificatePath))
        let wxCertContent = try String(contentsOf: URL(fileURLWithPath: wxCertificatePath))
        try self.init(apiV3Secret: apiV3Secret, certificateContent: certContent, wxCertificateContent: wxCertContent, mchid: mchid, serialNo: serialNo)
    }
    
    deinit {
        try? self.client.httpClient.syncShutdown()
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
