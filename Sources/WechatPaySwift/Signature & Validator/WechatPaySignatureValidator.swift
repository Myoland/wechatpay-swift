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
    public init(wxCertContent: String) {
        self.wxCertContent = wxCertContent
    }
    
    let wxCertContent: String
    
    public func verify(timestamp: String, nonce: String, body: String, signature: String) -> Bool {
        let message =
        """
        \(timestamp)\n\(nonce)\n\(body)\n
        """
        
        if RSASigner.verify(signature: signature, message: message, with: wxCertContent) {
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
