//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/5/28.
//

import Foundation
import Alamofire
import JWTKit

enum SignatureError: Error {
case responseSignatureNotMatch
}

public struct WechatPaySignatureValidator {
    let wxCertPath: String
    
    public func validate(timestamp: String, nonce: String, body: String, signature: String) -> Bool {
        let certPath = self.wxCertPath
        
        let message =
        """
        \(timestamp)\n\(nonce)\n\(body)\n
        """
        
        print(message)
        
        let pemString = try! String(contentsOf: URL(fileURLWithPath: certPath))
        
        if RSASigner.verify(signature: signature, message: message, with: pemString) {
            return true
        } else {
            return false
        }
    }
    
    var validation: DataRequest.Validation {
        let validator = self
        let customValidator: DataRequest.Validation = { (request, response, data) -> Request.ValidationResult in
            
            guard let timestamp = response.headers.value(for: "Wechatpay-Timestamp"),
                  let nonce = response.headers.value(for: "Wechatpay-Nonce"),
                  let data = data,
                  let body = String(data: data, encoding: .utf8),
                  let signature = response.headers.value(for: "Wechatpay-Signature") else {
                return Request.ValidationResult.failure(SignatureError.responseSignatureNotMatch)
                }
                  
            
            if validator.validate(timestamp: timestamp, nonce: nonce, body: body, signature: signature) {
                return Request.ValidationResult.success(())
            } else {
                return Request.ValidationResult.failure(SignatureError.responseSignatureNotMatch)
            }
        }
        
        return customValidator
    }
    
    init(wxCertPath: String) {
        self.wxCertPath = wxCertPath
    }
}
