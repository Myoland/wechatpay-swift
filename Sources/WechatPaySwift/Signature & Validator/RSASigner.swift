//  Created by kevinzhow on 2022/5/28.
//

import Foundation
import JWTKit

struct RSASigner {

    /// 使用 RSA 算法签名
    /// - Parameter text: 明文
    /// - Parameter privateKeyPem: RSA PrivateKey Pem
    static func sign(text: String, privateKeyPem: String) -> String? {
        guard let privateKey = try? RSAKey.private(pem: privateKeyPem) else { return nil }
        
        let signer = JWTSigner.rs256(key: privateKey)
        
        guard let data = try? signer.algorithm.sign(Data(text.utf8)) else { return nil }
        
        return Data(data).base64EncodedString()
    }


    /// 验证签名
    /// - Parameter signature: 签名字符串
    /// - Parameter text: 明文
    /// - Parameter pem: 证书
    static func verify(signature: String, message: String, with pem: String) -> Bool {
        
        guard let signatureData = Data(base64Encoded: signature) else {
            return false
        }

        do {
            let certKey = try RSAKey.certificate(pem: pem)
            let signer = JWTSigner.rs256(key: certKey)
            return try signer.algorithm.verify(signatureData, signs: Data(message.utf8))
        } catch {
            return false
        }
    }
}
