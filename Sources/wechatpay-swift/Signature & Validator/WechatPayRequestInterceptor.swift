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

enum WechatPayRequestInterceptorError: Error {
    case invalidCert
    case failedToParseBody
    case failedToSignBody
    case unsupportedHTTPMethodToSign
}

struct WechatPayRequestInterceptor {
    
    private let mchid: String
    private let serialNo: String
    private let certificatePath: String
    private let privateKeyPem: String
    
    init(mchid: String, serialNo: String, certificatePath: String) {
        self.mchid = mchid
        self.serialNo = serialNo
        self.certificatePath = certificatePath
        self.privateKeyPem = try! String(contentsOf: URL(fileURLWithPath: certificatePath))
    }
    
    func adapt(urlRequest: inout HTTPClientRequest) async throws {

        let timestamp = Int(Date().timeIntervalSince1970)
        let nonceStr = UUID().uuidString
        
        let sign = try await urlRequest.genSign(nonceStr: nonceStr, timestamp: timestamp, privateKeyPem: privateKeyPem)
        
        let signature =
        """
        mchid="\(mchid)",nonce_str="\(nonceStr)",signature="\(sign)",timestamp="\(timestamp)",serial_no="\(serialNo)"
        """
        
        urlRequest.headers.replaceOrAdd(name: "Authorization" , value: "WECHATPAY2-SHA256-RSA2048 \(signature)")
        urlRequest.headers.replaceOrAdd(name: "Accept", value: "application/json")
        urlRequest.headers.replaceOrAdd(name: "User-Agent", value: "WechatPay")
        urlRequest.headers.replaceOrAdd(name: "Accept-Language", value: "zh-CN")
    }
}

extension HTTPClientRequest {
    func genSign(nonceStr: String, timestamp: Int, privateKeyPem: String) async throws -> String {
        let urlRequest = self
        
        var body: String {
            get async throws {
                switch urlRequest.method {
                case  HTTPMethod.POST, HTTPMethod.PUT:
                    guard var bodyBuffer = try await urlRequest.body?.collect(upTo: 1024*1024),
                          let bodyData =  bodyBuffer.readData(length: bodyBuffer.readableBytes),
                          let bodyString = String(data: bodyData, encoding: .utf8) else {
                        return ""
                    }
                    return bodyString
                default:
                    return ""
                }
            }
        }
        
        let message =
        """
        \(urlRequest.method.rawValue)\n\(URL(string: urlRequest.url)!.pathWithQuery)\n\(timestamp)\n\(nonceStr)\n\(try await body)\n
        """
        
        print(message)
        
        return RSASigner.sign(text: message, privateKeyPem: privateKeyPem)!
    }
}
