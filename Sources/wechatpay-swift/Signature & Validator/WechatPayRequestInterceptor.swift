//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/5/27.
//

import Foundation
import Alamofire
import Crypto
import JWTKit

enum WechatPayRequestInterceptorError: Error {
    case invalidCert
}

final class WechatPayRequestInterceptor: Alamofire.RequestInterceptor {
    
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
    
    func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        
        var urlRequest = urlRequest
        
        let timestamp = Int(Date().timeIntervalSince1970)
        let nonceStr = UUID().uuidString
        
        let sign = urlRequest.genSign(nonceStr: nonceStr, timestamp: timestamp, privateKeyPem: privateKeyPem)
        
        let signature =
        """
        mchid="\(mchid)",nonce_str="\(nonceStr)",signature="\(sign)",timestamp="\(timestamp)",serial_no="\(serialNo)"
        """
        
        urlRequest.setValue("WECHATPAY2-SHA256-RSA2048 \(signature)", forHTTPHeaderField: "Authorization")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        urlRequest.setValue("Alamofire", forHTTPHeaderField: "User-Agent")
        urlRequest.setValue("zh-CN", forHTTPHeaderField: "Accept-Language")
        
        completion(.success(urlRequest))
    }
}

extension URLRequest {
    func genSign(nonceStr: String, timestamp: Int, privateKeyPem: String) -> String {
        let urlRequest = self
        
        var body: String {
            switch urlRequest.method {
            case  HTTPMethod.post, HTTPMethod.put:
                guard let bodyData = urlRequest.httpBody, let bodyString = String(data: bodyData, encoding: .utf8) else {
                    return ""
                }
                
                return bodyString
            default:
                return ""
            }
        }
        
        let message =
        """
        \(urlRequest.method!.rawValue)\n\(urlRequest.url!.pathWithQuery)\n\(timestamp)\n\(nonceStr)\n\(body)\n
        """
        
        print(message)
    
        return RSASigner.sign(text: message, privateKeyPem: privateKeyPem)!
    }
}
