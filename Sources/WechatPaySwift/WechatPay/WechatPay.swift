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
                serialNo: String,
                clock: @escaping @Sendable () -> Date = { Date() }) throws {
        self.apiV3Secret = apiV3Secret
        self.certificateContent = certificateContent
        self.mchid = mchid
        self.serialNo = serialNo
        self.wxCertificateContent = wxCertificateContent
        self.decoder.dateDecodingStrategy = .iso8601
        self.client = WechatPay.Client(httpClient: HTTPClient(eventLoopGroupProvider: .singleton), requestInterceptor: WechatPayRequestInterceptor(mchid: mchid, serialNo: serialNo, certificateContent: certificateContent), validator: WechatPaySignatureValidator(wxCertContent: wxCertificateContent, clock: clock))
    }
    
    public convenience init(apiV3Secret: String,
                certificatePath: String,
                wxCertificatePath: String,
                mchid: String,
                serialNo: String,
                clock: @escaping @Sendable () -> Date = { Date() }) throws {
       
        let certContent = try String(contentsOf: URL(fileURLWithPath: certificatePath))
        let wxCertContent = try String(contentsOf: URL(fileURLWithPath: wxCertificatePath))
        try self.init(apiV3Secret: apiV3Secret, certificateContent: certContent, wxCertificateContent: wxCertContent, mchid: mchid, serialNo: serialNo, clock: clock)
    }

    public init(apiV3Secret: String,
                certificateContent: String,
                wxCertificateContent: String = "",
                mchid: String,
                serialNo: String,
                certificateProvider: any WechatPayPlatformCertificateProvider,
                clock: @escaping @Sendable () -> Date = { Date() }) throws {
        self.apiV3Secret = apiV3Secret
        self.certificateContent = certificateContent
        self.wxCertificateContent = wxCertificateContent
        self.mchid = mchid
        self.serialNo = serialNo
        self.decoder.dateDecodingStrategy = .iso8601
        self.client = WechatPay.Client(
            httpClient: HTTPClient(eventLoopGroupProvider: .singleton),
            requestInterceptor: WechatPayRequestInterceptor(mchid: mchid, serialNo: serialNo, certificateContent: certificateContent),
            validator: WechatPaySignatureValidator(certificateProvider: certificateProvider, clock: clock))
    }

    public convenience init(apiV3Secret: String,
                            certificateContent: String,
                            certificateProvider: any WechatPayPlatformCertificateProvider,
                            mchid: String,
                            serialNo: String,
                            clock: @escaping @Sendable () -> Date = { Date() }) throws {
        try self.init(apiV3Secret: apiV3Secret, certificateContent: certificateContent,
                      mchid: mchid, serialNo: serialNo, certificateProvider: certificateProvider, clock: clock)
    }

    public func verifyNotification(serialNumber: String, timestamp: String, nonce: String, body: String, signature: String) async throws -> Bool {
        try await client.validator.verify(serialNumber: serialNumber, timestamp: timestamp, nonce: nonce, body: body, signature: signature)
    }
    
    deinit {
        // A request-scoped client can be released on a NIO event loop. Never block it.
        self.client.httpClient.shutdown { _ in }
    }
}


extension WechatPay {
    func decodeCiphertext(ciphertext: String, nonce: String, tag: String) throws -> String {
        try WechatPayAEAD.decrypt(ciphertext: ciphertext, nonce: nonce,
                                  associatedData: tag, apiV3Secret: apiV3Secret)
    }
}
