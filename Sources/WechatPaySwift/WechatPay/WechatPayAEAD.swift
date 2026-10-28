import Foundation
import Crypto

/// Redacted resource-decryption failures; no merchant keys or remote payloads are included.
public enum WechatPayDecryptionError: Error, Equatable, Sendable {
    case invalidAPIv3Key
    case invalidCiphertext
    case invalidNonce
    case authenticationFailed
    case invalidPlaintext
}

/// Shared by notification-resource and platform-certificate decryption.
enum WechatPayAEAD {
    static func decrypt(ciphertext: String, nonce: String, associatedData: String, apiV3Secret: String) throws -> String {
        guard apiV3Secret.utf8.count == 32 else { throw WechatPayDecryptionError.invalidAPIv3Key }
        guard let encrypted = Data(base64Encoded: ciphertext), encrypted.count >= 16 else {
            throw WechatPayDecryptionError.invalidCiphertext
        }
        guard nonce.utf8.count == 12 else { throw WechatPayDecryptionError.invalidNonce }
        let plaintext: Data
        do {
            let nonceValue = try AES.GCM.Nonce(data: Data(nonce.utf8))
            let box = try AES.GCM.SealedBox(nonce: nonceValue, ciphertext: encrypted.dropLast(16), tag: encrypted.suffix(16))
            plaintext = try AES.GCM.open(box, using: SymmetricKey(data: Data(apiV3Secret.utf8)),
                                         authenticating: Data(associatedData.utf8))
        } catch { throw WechatPayDecryptionError.authenticationFailed }
        guard let text = String(data: plaintext, encoding: .utf8) else {
            throw WechatPayDecryptionError.invalidPlaintext
        }
        return text
    }
}
