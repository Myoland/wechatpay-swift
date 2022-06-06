//  Created by kevinzhow on 2022/5/28.
//

import Foundation
import JWTKit

struct RSASigner {

    /// 使用 RSA 算法签名
    /// - Parameter text: 明文
    /// - Parameter privateKeyPem: RSA PrivateKey Pem
    static func sign(text: String, privateKeyPem: String) -> String? {
        let privateKey = try! RSAKey.private(pem: privateKeyPem)
        
        let signer = JWTSigner.rs256(key: privateKey)
        
        let data = try! signer.algorithm.sign(text.data(using: .utf8)!)
        
        return Data(data).base64EncodedString()
    }


    /// 验证签名
    /// - Parameter signature: 签名字符串
    /// - Parameter text: 明文
    /// - Parameter pem: 证书
    static func verify(signature: String, message: String, with pem: String) -> Bool {
        
        let ceryKey = try! RSAKey.certificate(pem: pem)
        
        let signer = JWTSigner.rs256(key: ceryKey)

        if try! signer.algorithm.verify(Data(base64Encoded: signature)!, signs: message.data(using: .utf8)!) {
            return true
        } else {
            return false
        }
    }
}
