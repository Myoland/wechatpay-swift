//
//  File.swift
//
//
//  Created by kevinzhow on 2022/5/27.
//

import Foundation
import Crypto
import JWTKit
import AsyncHTTPClient
import NIOHTTP1

public enum WechatPayRequestSigningError: Error, Equatable {
    case invalidURL
}

enum WechatPayRequestInterceptorError: Error {
    case invalidCert
    case failedToParseBody
    case failedToSignBody
    case unsupportedHTTPMethodToSign
}

struct WechatPayRequestInterceptor {
    
    private let mchid: String
    private let serialNo: String
    private let certificateContent: String
    let responsePublicKey: TrustedWechatPublicKey?
    
    init(mchid: String, serialNo: String, certificateContent: String,
         responsePublicKey: TrustedWechatPublicKey? = nil) {
        self.mchid = mchid
        self.serialNo = serialNo
        self.certificateContent = certificateContent
        self.responsePublicKey = responsePublicKey
    }
    
    func adapt(urlRequest: inout HTTPClientRequest) async throws {

        let timestamp = Int(Date().timeIntervalSince1970)
        let nonceStr = UUID().uuidString
        
        let sign = try await urlRequest.genSign(nonceStr: nonceStr, timestamp: timestamp, privateKeyPem: certificateContent)
        
        let signature =
        """
        mchid="\(mchid)",nonce_str="\(nonceStr)",signature="\(sign)",timestamp="\(timestamp)",serial_no="\(serialNo)"
        """
        
        urlRequest.headers.replaceOrAdd(name: "Authorization" , value: "WECHATPAY2-SHA256-RSA2048 \(signature)")
        urlRequest.headers.replaceOrAdd(name: "Accept", value: "application/json")
        urlRequest.headers.replaceOrAdd(name: "User-Agent", value: "WechatPay")
        urlRequest.headers.replaceOrAdd(name: "Accept-Language", value: "zh-CN")
        // Select WeChat's response signing key during the merchant's migration.
        // Authorization.serial_no above still identifies the merchant signing certificate.
        if let responsePublicKey {
            urlRequest.headers.replaceOrAdd(name: "Wechatpay-Serial", value: responsePublicKey.id)
        }
    }
}

extension HTTPClientRequest {
    func genSign(nonceStr: String, timestamp: Int, privateKeyPem: String) async throws -> String {
        let urlRequest = self
        guard let url = URL(string: urlRequest.url) else {
            throw WechatPayRequestSigningError.invalidURL
        }
        
        var body: String {
            get async throws {
                switch urlRequest.method {
                case  HTTPMethod.POST, HTTPMethod.PUT:
                    guard var bodyBuffer = try await urlRequest.body?.collect(upTo: 1024*1024) else {
                        return ""
                    }
                    let bodyString = String(buffer: bodyBuffer)
                    return bodyString
                default:
                    return ""
                }
            }
        }
        
        let message =
        """
        \(urlRequest.method.rawValue)\n\(url.pathWithQuery)\n\(timestamp)\n\(nonceStr)\n\(try await body)\n
        """
        
        guard let signature = RSASigner.sign(text: message, privateKeyPem: privateKeyPem) else {
            throw WechatPayRequestInterceptorError.failedToSignBody
        }
        return signature
    }
}
