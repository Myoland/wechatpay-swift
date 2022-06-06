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
    
    private let wechatPay: WechatPay
    private let privateKeyPem: String
    
    init(wechatPay: WechatPay) {
        self.wechatPay = wechatPay
        
        self.privateKeyPem =  try! String(contentsOf: URL(fileURLWithPath: wechatPay.certificatePath))
    }
    
    func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        
        var urlRequest = urlRequest
        
        let timestamp = Int(Date().timeIntervalSince1970)
        let nonceStr = UUID().uuidString
        
        let sign = urlRequest.genSign(nonceStr: nonceStr, timestamp: timestamp, privateKeyPem: privateKeyPem)
        
        let signature =
        """
        mchid="\(wechatPay.mchid)",nonce_str="\(nonceStr)",signature="\(sign)",timestamp="\(timestamp)",serial_no="\(wechatPay.serialNo)"
        """
        
        urlRequest.setValue("WECHATPAY2-SHA256-RSA2048 \(signature)", forHTTPHeaderField: "Authorization")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        urlRequest.setValue("Alamofire", forHTTPHeaderField: "User-Agent")
        urlRequest.setValue("zh-CN", forHTTPHeaderField: "Accept-Language")
        
        completion(.success(urlRequest))
    }
    
    //    func retry(_ request: Request, for session: Session, dueTo error: Error, completion: @escaping (RetryResult) -> Void) {
    //        guard let response = request.task?.response as? HTTPURLResponse, response.statusCode == 401 else {
    //            /// The request did not fail due to a 401 Unauthorized response.
    //            /// Return the original error and don't retry the request.
    //            return completion(.doNotRetryWithError(error))
    //        }
    //
    //        refreshToken { [weak self] result in
    //            guard let self = self else { return }
    //
    //            switch result {
    //            case .success(let token):
    //                self.storage.accessToken = token
    //                /// After updating the token we can safely retry the original request.
    //                completion(.retry)
    //            case .failure(let error):
    //                completion(.doNotRetryWithError(error))
    //            }
    //        }
    //    }
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
