import Foundation
import AsyncHTTPClient
import NIOHTTP1

public struct WechatPaySignatureValidator: Sendable {
    public typealias Clock = @Sendable () -> Date
    private let legacyPEM: String?
    private let provider: any WechatPayPlatformCertificateProvider
    private let clock: Clock

    public init(wxCertContent: String, clock: @escaping Clock = { Date() }) {
        self.legacyPEM = wxCertContent
        self.provider = SingleCertificateProvider(pem: wxCertContent, clock: clock)
        self.clock = clock
    }

    public init(wxCertPath: String, clock: @escaping Clock = { Date() }) throws {
        self.init(wxCertContent: try String(contentsOfFile: wxCertPath), clock: clock)
    }

    public init(certificateProvider: any WechatPayPlatformCertificateProvider, clock: @escaping Clock = { Date() }) {
        self.legacyPEM = nil
        self.provider = certificateProvider
        self.clock = clock
    }

    /// Legacy synchronous verification retained for source compatibility. New notification
    /// integrations must use the asynchronous serial-selecting overload below.
    @available(*, deprecated, message: "Use verify(serialNumber:timestamp:nonce:body:signature:) or WechatPay.verifyNotification for rotation-aware verification.")
    public func verify(timestamp: String, nonce: String, body: String, signature: String) -> Bool {
        guard let legacyPEM else { return false }
        return RSASigner.verify(signature: signature, message: "\(timestamp)\n\(nonce)\n\(body)\n", with: legacyPEM)
    }

    public func verify(serialNumber: String, timestamp: String, nonce: String, body: String, signature: String) async throws -> Bool {
        // Reject stale/malformed messages before key lookup can trigger certificate refresh.
        _ = try Self.validatedTimestamp(timestamp, now: clock(), requireFresh: true)
        guard let decoded = Data(base64Encoded: signature), !decoded.isEmpty else {
            return false
        }
        let identifier = try WechatPayVerificationKey.normalizedIdentifier(serialNumber)
        let key = try await provider.verificationKey(for: identifier)
        guard key.identifier == identifier else { throw WechatPayPlatformCertificateError.serialNumberMismatch }
        return key.verify(signature: signature, message: "\(timestamp)\n\(nonce)\n\(body)\n")
    }

    static func validatedTimestamp(_ timestamp: String, now: Date, requireFresh: Bool) throws -> Date {
        guard !timestamp.isEmpty, timestamp.utf8.count <= 19,
              timestamp.utf8.allSatisfy({ (48...57).contains($0) }),
              let seconds = Int64(timestamp), seconds > 0,
              now.timeIntervalSince1970.isFinite else {
            throw WechatPayPlatformCertificateError.invalidTimestamp
        }
        let signedAt = Date(timeIntervalSince1970: TimeInterval(seconds))
        let age = now.timeIntervalSince(signedAt)
        // The official Java validator rejects an absolute age of five minutes or more.
        guard age > -300, !requireFresh || age < 300 else {
            throw WechatPayPlatformCertificateError.invalidTimestamp
        }
        return signedAt
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
    let clock: WechatPaySignatureValidator.Clock
    func certificate(for serialNumber: String) async throws -> WechatPayPlatformCertificate {
        let certificate = try WechatPayPlatformCertificate(pem: pem, expectedSerialNumber: serialNumber)
        guard certificate.isValid(at: clock()) else {
            throw WechatPayPlatformCertificateError.certificateNotCurrentlyValid
        }
        return certificate
    }
}
