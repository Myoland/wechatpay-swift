import Foundation
import AsyncHTTPClient
import Crypto
import NIOHTTP1

/// Persist the original authenticated encrypted response, not an unverified list of PEMs.
/// Reload it through verifyCachedEnvelope in the same merchant/APIv3-key scope.
public struct WechatPayPlatformCertificateEnvelope: Codable, Sendable {
    public let body: Data
    public let serialNumber: String
    public let timestamp: String
    public let nonce: String
    public let signature: String

    public init(body: Data, serialNumber: String, timestamp: String, nonce: String, signature: String) {
        self.body = body
        self.serialNumber = serialNumber
        self.timestamp = timestamp
        self.nonce = nonce
        self.signature = signature
    }
}

public struct WechatPayVerifiedPlatformCertificateBundle: Sendable {
    public let certificates: [WechatPayPlatformCertificate]
    public let envelope: WechatPayPlatformCertificateEnvelope
}

/// Independent of WechatPay and its provider, so a refresh closure need not retain either.
/// The sole bootstrap exception is the fixed TLS certificate endpoint: authenticate and
/// decrypt with APIv3, parse X.509, then verify this same response with its selected cert.
/// Ordinary API responses never bypass their provider's signature validation.
public struct WechatPayPlatformCertificateDownloader: Sendable {
    public typealias Clock = @Sendable () -> Date
    private static let endpoint = "https://api.mch.weixin.qq.com/v3/certificates"
    private let apiV3Secret: String
    private let merchantCertificateContent: String
    private let merchantID: String
    private let merchantCertificateSerialNumber: String
    private let clock: Clock
    private let trustedPublicKeys: [TrustedWechatPublicKey]
    private let testTransport: Transport?

    struct TransportResponse: Sendable {
        let status: Int
        let headers: HTTPHeaders
        let body: Data
    }
    typealias Transport = @Sendable (HTTPClientRequest) async throws -> TransportResponse

    public init(
        apiV3Secret: String,
        merchantCertificateContent: String,
        merchantID: String,
        merchantCertificateSerialNumber: String,
        clock: @escaping Clock = { Date() },
        trustedPublicKeys: [TrustedWechatPublicKey] = []
    ) {
        self.apiV3Secret = apiV3Secret
        self.merchantCertificateContent = merchantCertificateContent
        self.merchantID = merchantID
        self.merchantCertificateSerialNumber = merchantCertificateSerialNumber
        self.clock = clock
        self.trustedPublicKeys = trustedPublicKeys
        self.testTransport = nil
    }

    // An internal seam for offline tests; production cannot redirect the certificate endpoint.
    init(
        apiV3Secret: String,
        merchantCertificateContent: String,
        merchantID: String,
        merchantCertificateSerialNumber: String,
        clock: @escaping Clock,
        trustedPublicKeys: [TrustedWechatPublicKey] = [],
        testTransport: @escaping Transport
    ) {
        self.apiV3Secret = apiV3Secret
        self.merchantCertificateContent = merchantCertificateContent
        self.merchantID = merchantID
        self.merchantCertificateSerialNumber = merchantCertificateSerialNumber
        self.clock = clock
        self.trustedPublicKeys = trustedPublicKeys
        self.testTransport = testTransport
    }

    public func download() async throws -> WechatPayVerifiedPlatformCertificateBundle {
        var request = HTTPClientRequest(url: Self.endpoint)
        request.method = .GET
        let signer = WechatPayRequestInterceptor(
            mchid: merchantID, serialNo: merchantCertificateSerialNumber,
            certificateContent: merchantCertificateContent)
        try await signer.adapt(urlRequest: &request)
        let response = try await fetch(request)
        guard response.status == 200, response.body.count <= 1024 * 1024 else {
            throw WechatPayPlatformCertificateError.invalidResponse
        }
        let headers = try WechatPaySignatureValidator.signatureHeaders(response.headers)
        let envelope = WechatPayPlatformCertificateEnvelope(
            body: response.body, serialNumber: headers.serialNumber,
            timestamp: headers.timestamp, nonce: headers.nonce, signature: headers.signature)
        let certificates = try verify(envelope, requireFreshTimestamp: true)
        return WechatPayVerifiedPlatformCertificateBundle(certificates: certificates, envelope: envelope)
    }

    public func verifyCachedEnvelope(_ envelope: WechatPayPlatformCertificateEnvelope) throws -> [WechatPayPlatformCertificate] {
        try verify(envelope, requireFreshTimestamp: false)
    }

    public func verifyCachedEnvelopeBundle(_ envelope: WechatPayPlatformCertificateEnvelope) throws -> WechatPayVerifiedPlatformCertificateBundle {
        WechatPayVerifiedPlatformCertificateBundle(
            certificates: try verifyCachedEnvelope(envelope), envelope: envelope)
    }

    private func verify(_ envelope: WechatPayPlatformCertificateEnvelope, requireFreshTimestamp: Bool) throws -> [WechatPayPlatformCertificate] {
        guard envelope.body.count <= 1024 * 1024, apiV3Secret.utf8.count == 32 else {
            throw WechatPayPlatformCertificateError.invalidResponse
        }
        let signedAt: Date
        do { signedAt = try WechatPaySignatureValidator.validatedTimestamp(envelope.timestamp, now: clock(), requireFresh: requireFreshTimestamp) }
        catch { throw WechatPayPlatformCertificateError.invalidResponse }
        let serial = try WechatPayVerificationKey.normalizedIdentifier(envelope.serialNumber)
        let publicKey: TrustedWechatPublicKey?
        if serial.hasPrefix("PUB_KEY_ID_") {
            guard trustedPublicKeys.count <= 32,
                  let configured = trustedPublicKeys.first(where: { $0.id == serial }),
                  trustedPublicKeys.filter({ $0.id == serial }).allSatisfy({ $0.pem == configured.pem }) else {
                throw WechatPayPlatformCertificateError.unknownPublicKeyID
            }
            publicKey = configured
        } else { publicKey = nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let value = try decoder.singleValueContainer().decode(String.self)
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = formatter.date(from: value) { return date }
            formatter.formatOptions = [.withInternetDateTime]
            guard let date = formatter.date(from: value) else {
                throw WechatPayPlatformCertificateError.invalidResponse
            }
            return date
        }
        let payload: WechatCertificateResponse
        do { payload = try decoder.decode(WechatCertificateResponse.self, from: envelope.body) }
        catch { throw WechatPayPlatformCertificateError.invalidResponse }
        guard !payload.data.isEmpty, payload.data.count <= 32 else {
            throw WechatPayPlatformCertificateError.invalidResponse
        }
        var certificates: [String: WechatPayPlatformCertificate] = [:]
        for entry in payload.data {
            let encrypted = entry.encryptCertificate
            guard encrypted.algorithm == "AEAD_AES_256_GCM" else {
                throw WechatPayPlatformCertificateError.invalidEncryptedCertificate
            }
            let pem: String
            do {
                pem = try WechatPayAEAD.decrypt(ciphertext: encrypted.ciphertext, nonce: encrypted.nonce,
                                                associatedData: encrypted.associatedData, apiV3Secret: apiV3Secret)
            } catch { throw WechatPayPlatformCertificateError.invalidEncryptedCertificate }
            let certificate = try WechatPayPlatformCertificate(pem: pem, expectedSerialNumber: entry.serialNo)
            guard abs(certificate.notValidBefore.timeIntervalSince(entry.effectiveTime)) < 0.001,
                  abs(certificate.notValidAfter.timeIntervalSince(entry.expireTime)) < 0.001,
                  certificates[certificate.serialNumber] == nil else {
                throw WechatPayPlatformCertificateError.certificateMetadataMismatch
            }
            certificates[certificate.serialNumber] = certificate
        }
        guard let body = String(data: envelope.body, encoding: .utf8) else {
            throw WechatPayPlatformCertificateError.invalidResponse
        }
        let verificationKey: WechatPayVerificationKey
        if let publicKey { verificationKey = .publicKey(publicKey) }
        else if let signingCertificate = certificates[serial], signingCertificate.isValid(at: signedAt) {
            verificationKey = .certificate(signingCertificate)
        } else { throw WechatPayPlatformCertificateError.invalidSignature }
        guard verificationKey.verify(
                signature: envelope.signature,
                message: "\(envelope.timestamp)\n\(envelope.nonce)\n\(body)\n") else {
            throw WechatPayPlatformCertificateError.invalidSignature
        }
        // Historical cache authenticity uses the authenticated download timestamp.
        // Current notifications/API responses check the chosen key at the current clock.
        return certificates.values.sorted { $0.serialNumber < $1.serialNumber }
    }

    private func fetch(_ request: HTTPClientRequest) async throws -> TransportResponse {
        if let testTransport { return try await testTransport(request) }
        let client = HTTPClient(
            eventLoopGroupProvider: .singleton,
            configuration: HTTPClient.Configuration(redirectConfiguration: .disallow))
        do {
            let response = try await client.execute(request, timeout: .seconds(30))
            let body = try await response.body.collect(upTo: 1024 * 1024)
            let result = TransportResponse(status: Int(response.status.code), headers: response.headers, body: Data(buffer: body))
            await close(client)
            return result
        } catch {
            await close(client)
            throw error
        }
    }

    private func close(_ client: HTTPClient) async {
        await withCheckedContinuation { continuation in
            client.shutdown { _ in continuation.resume() }
        }
    }
}
