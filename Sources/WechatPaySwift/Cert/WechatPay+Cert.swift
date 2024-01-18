//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/5/28.
//

import Foundation
import Crypto

extension WechatPay {
    /// 下载微信平台证书
    func downloadCertificates() async throws -> WechatCertificateResponse {
        
        let entry = WechatPayAPIEntry.downloadCertificates
        
        let response: WechatCertificateResponse = try await self.client.request(
            "\(entry.absolutePath)",
            method: entry.method,
            decoder: self.decoder
        )
        
        return response
    }
    
    func decodeCert(cert: WechatCertificateResponse.Data) throws -> String {
        let ciphertext = cert.encryptCertificate.ciphertext
        let nonce = cert.encryptCertificate.nonce
        let tag = cert.encryptCertificate.associatedData
        
        return try self.decodeCiphertext(ciphertext: ciphertext, nonce: nonce, tag: tag)
    }
}
