//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/5/28.
//

import Foundation
import Alamofire
import Crypto

extension WechatPay {
    /// 下载微信平台证书
    func downloadCertificates() async throws -> DataResponse<WechatCertificateResponse, AFError> {
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        let response = await AF.request(
            "\(WechatPayURL.host)\(WechatPayAPIEntry.downloadCertificates.path)",
            method: WechatPayAPIEntry.downloadCertificates.method,
            interceptor: self.interceptor
        ).validate(self.validator.validation).serializingDecodable(WechatCertificateResponse.self, decoder: decoder).response
        
        return response
    }
    
    func decodeCert(cert: WechatCertificateResponse.Data) throws -> String {
        let ciphertext = cert.encryptCertificate.ciphertext
        let nonce = cert.encryptCertificate.nonce
        let tag = cert.encryptCertificate.associatedData
        
        return try self.decodeCiphertext(ciphertext: ciphertext, nonce: nonce, tag: tag)
    }
}
