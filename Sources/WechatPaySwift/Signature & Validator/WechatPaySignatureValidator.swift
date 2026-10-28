import Foundation
import AsyncHTTPClient
import NIOHTTP1

public struct WechatPaySignatureValidator: Sendable {
    private let legacyPEM: String?
    private let provider: any WechatPayPlatformCertificateProvider

    public init(wxCertContent: String) {
        self.legacyPEM = wxCertContent
        self.provider = SingleCertificateProvider(pem: wxCertContent)
    }

    public init(wxCertPath: String) throws {
        self.init(wxCertContent: try String(contentsOfFile: wxCertPath))
    }

    public init(certificateProvider: any WechatPayPlatformCertificateProvider) {
        self.legacyPEM = nil
        self.provider = certificateProvider
    }

    /// Legacy synchronous verification retained for source compatibility. New notification
    /// integrations must use the asynchronous serial-selecting overload below.
    public func verify(timestamp: String, nonce: String, body: String, signature: String) -> Bool {
        guard let legacyPEM else { return false }
        return RSASigner.verify(signature: signature, message: "\(timestamp)\n\(nonce)\n\(body)\n", with: legacyPEM)
    }

    public func verify(serialNumber: String, timestamp: String, nonce: String, body: String, signature: String) async throws -> Bool {
        let identifier = try WechatPayVerificationKey.normalizedIdentifier(serialNumber)
        let key = try await provider.verificationKey(for: identifier)
        guard key.identifier == identifier else { throw WechatPayPlatformCertificateError.serialNumberMismatch }
        return key.verify(signature: signature, message: "\(timestamp)\n\(nonce)\n\(body)\n")
    }

    public func validate(response: HTTPClientResponse, body: String) async throws {
        let headers = try Self.signatureHeaders(response.headers)
        guard try await verify(
            serialNumber: headers.serialNumber, timestamp: headers.timestamp,
            nonce: headers.nonce, body: body, signature: headers.signature) else {
            throw WechatPayPlatformCertificateError.invalidSignature
        }
    }

    static func signatureHeaders(_ headers: HTTPHeaders) throws -> SignatureHeaders {
        func single(_ name: String) throws -> String {
            let values = headers[name]
            guard values.count == 1, let value = values.first, !value.isEmpty else {
                throw WechatPayPlatformCertificateError.missingSignatureHeaders
            }
            return value
        }
        return try SignatureHeaders(
            serialNumber: single("Wechatpay-Serial"), timestamp: single("Wechatpay-Timestamp"),
            nonce: single("Wechatpay-Nonce"), signature: single("Wechatpay-Signature"))
    }

    struct SignatureHeaders {
        let serialNumber: String
        let timestamp: String
        let nonce: String
        let signature: String
    }
}

private struct SingleCertificateProvider: WechatPayPlatformCertificateProvider {
    let pem: String
    func certificate(for serialNumber: String) async throws -> WechatPayPlatformCertificate {
        let certificate = try WechatPayPlatformCertificate(pem: pem, expectedSerialNumber: serialNumber)
        guard certificate.isValid(at: Date()) else {
            throw WechatPayPlatformCertificateError.certificateNotCurrentlyValid
        }
        return certificate
    }
}
