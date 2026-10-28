import Foundation
import JWTKit

/// A platform public key explicitly provisioned by the merchant. A notification or
/// downloaded certificate response can never add a key to this trust set.
public struct TrustedWechatPublicKey: Sendable {
    public let id: String
    public let pem: String

    public init(id: String, pem: String) throws {
        self.id = try Self.validateID(id)
        let normalized = pem.replacingOccurrences(of: "\r\n", with: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.utf8.count <= 64 * 1024,
              normalized.hasPrefix("-----BEGIN PUBLIC KEY-----"),
              normalized.components(separatedBy: "-----BEGIN ").count == 2,
              normalized.components(separatedBy: "-----END ").count == 2,
              normalized.hasSuffix("-----END PUBLIC KEY-----"),
              !normalized.contains("PRIVATE KEY"),
              (try? RSAKey.public(pem: normalized)) != nil else {
            throw WechatPayPlatformCertificateError.invalidPublicKey
        }
        self.pem = normalized + "\n"
    }

    static func validateID(_ id: String) throws -> String {
        let prefix = "PUB_KEY_ID_"
        guard id.hasPrefix(prefix), id.utf8.count <= 128, id.count > prefix.count,
              id.dropFirst(prefix.count).utf8.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 95
              }) else {
            throw WechatPayPlatformCertificateError.invalidPublicKey
        }
        return id
    }

    func verify(signature: String, message: String) -> Bool {
        guard let decoded = Data(base64Encoded: signature), let key = try? RSAKey.public(pem: pem) else { return false }
        return (try? JWTSigner.rs256(key: key).algorithm.verify(decoded, signs: Data(message.utf8))) == true
    }
}

public enum WechatPayVerificationKey: Sendable {
    case certificate(WechatPayPlatformCertificate)
    case publicKey(TrustedWechatPublicKey)

    public var identifier: String {
        switch self {
        case .certificate(let certificate): return certificate.serialNumber
        case .publicKey(let key): return key.id
        }
    }

    func verify(signature: String, message: String) -> Bool {
        switch self {
        case .certificate(let certificate): return RSASigner.verify(signature: signature, message: message, with: certificate.pem)
        case .publicKey(let key): return key.verify(signature: signature, message: message)
        }
    }

    static func normalizedIdentifier(_ value: String) throws -> String {
        value.hasPrefix("PUB_KEY_ID_")
            ? try TrustedWechatPublicKey.validateID(value)
            : try WechatPayPlatformCertificate.normalizeSerialNumber(value)
    }
}
