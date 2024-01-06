//
//  File.swift
//
//
//  Created by kevinzhow on 2022/5/28.
//

import Foundation
import JWTKit
import AsyncHTTPClient
import NIOCore

enum WechatPaySignatureValidatorError: Error {
    case responseSignatureNotMatch
    case failedToParseResponse
}

public struct WechatPaySignatureValidator {
    public init(wxCertPath: String) {
        self.wxCertPath = wxCertPath
    }
    
    let wxCertPath: String
    
    public func verify(timestamp: String, nonce: String, body: String, signature: String) -> Bool {
        let certPath = self.wxCertPath
        
        let message =
        """
        \(timestamp)\n\(nonce)\n\(body)\n
        """
        
        let pemString = try! String(contentsOf: URL(fileURLWithPath: certPath))
        
        if RSASigner.verify(signature: signature, message: message, with: pemString) {
            return true
        } else {
            return false
        }
    }
    
    public func validate(response: AsyncHTTPClient.HTTPClientResponse, body: String) async throws {
        
        guard let timestamp = response.headers.first(name: "Wechatpay-Timestamp"),
              let nonce = response.headers.first(name: "Wechatpay-Nonce"),
              let signature = response.headers.first(name: "Wechatpay-Signature") else {
            throw WechatPaySignatureValidatorError.failedToParseResponse
        }
        
        if verify(timestamp: timestamp, nonce: nonce, body: body, signature: signature) {
            return
        } else {
            throw WechatPaySignatureValidatorError.responseSignatureNotMatch
        }
    }
}
