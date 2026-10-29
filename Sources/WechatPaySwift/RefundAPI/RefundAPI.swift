//
//  RefundAPI.swift
//  APIv3 domestic refunds for directly connected merchants:
//  POST /v3/refund/domestic/refunds and GET /v3/refund/domestic/refunds/{out_refund_no}.
//

import Foundation
import NIOHTTP1

/// Redacted refund API failures. No provider message, body, key or credential is carried.
public enum WechatPayRefundError: Error, Equatable, Sendable {
    /// Rejected locally before any network activity.
    case invalidRequest
    /// No complete HTTP response was received (timeout, connection loss, ...). Outcome unknown.
    case transportFailed
    /// A non-200 response. Its body is NOT signature-verified; `code` is only a hint.
    case unexpectedStatus(Int, code: String?)
    /// A 200 response whose platform signature could not be verified.
    case invalidSignature
    /// A verified 200 response that is not a well-formed refund resource.
    case invalidResponse
    /// A notification that is not an authentic, well-formed refund notification.
    case invalidNotification
}

extension WechatPay {
    public struct RefundAPI {
        public let wechatPay: WechatPay

        public init(wechatPay: WechatPay) {
            self.wechatPay = wechatPay
        }

        /// Submits a domestic refund. The request body is encoded deterministically
        /// (`CreateRefundRequest.encodedBody()`), so a retry with the same request value
        /// sends byte-identical JSON with the same `out_refund_no`.
        public func create(_ request: CreateRefundRequest) async throws -> Refund {
            guard request.isValid else { throw WechatPayRefundError.invalidRequest }
            let body = try request.encodedBody()
            let entry = WechatPayAPIEntry.domesticRefunds
            return try await verified(url: entry.absolutePath, method: entry.method, body: body)
        }

        /// Queries a refund by the merchant refund number.
        public func query(outRefundNo: String) async throws -> Refund {
            guard CreateRefundRequest.isValidOutRefundNo(outRefundNo) else {
                throw WechatPayRefundError.invalidRequest
            }
            let entry = WechatPayAPIEntry.domesticRefunds
            return try await verified(url: "\(entry.absolutePath)/\(outRefundNo)", method: .GET, body: nil)
        }

        /// Decrypts and decodes the resource of a refund notification. The caller MUST first
        /// verify the notification signature (`WechatPay.verifyNotification`).
        public func decodeNotification(_ notification: WechatPay.H5API.PayNotification) throws -> RefundNotification {
            let expected: RefundNotification.Status
            switch notification.eventType {
            case .refundSuccess: expected = .success
            case .refundClosed: expected = .closed
            case .refundAbnormal: expected = .abnormal
            case .transactionSuccess: throw WechatPayRefundError.invalidNotification
            }
            guard notification.resource.originalType == "refund",
                  notification.resource.algorithm == "AEAD_AES_256_GCM",
                  notification.resource.ciphertext.utf8.count <= 64 * 1024 else {
                throw WechatPayRefundError.invalidNotification
            }
            let plaintext: String
            do {
                plaintext = try wechatPay.decodeCiphertext(ciphertext: notification.resource.ciphertext,
                                                           nonce: notification.resource.nonce,
                                                           tag: notification.resource.associatedData)
            } catch {
                throw WechatPayRefundError.invalidNotification
            }
            guard let resource = try? JSONDecoder().decode(RefundNotification.self, from: Data(plaintext.utf8)),
                  resource.refundStatus == expected else {
                throw WechatPayRefundError.invalidNotification
            }
            return resource
        }

        private func verified(url: String, method: HTTPMethod, body: Data?) async throws -> Refund {
            let response: WechatPayTransportResponse
            do {
                response = try await wechatPay.client.exchange(url, method: method, body: body)
            } catch {
                throw WechatPayRefundError.transportFailed
            }
            guard response.status == 200 else {
                throw WechatPayRefundError.unexpectedStatus(response.status, code: Self.errorCode(response.body))
            }
            do {
                try await wechatPay.client.validator.validate(
                    headers: response.headers, body: String(decoding: response.body, as: UTF8.self))
            } catch {
                throw WechatPayRefundError.invalidSignature
            }
            guard let refund = try? JSONDecoder().decode(Refund.self, from: response.body) else {
                throw WechatPayRefundError.invalidResponse
            }
            return refund
        }

        /// Extracts only an upper-case error code such as RESOURCE_NOT_EXISTS; never the message.
        static func errorCode(_ body: Data) -> String? {
            struct ErrorBody: Decodable { let code: String }
            guard body.count <= 64 * 1024,
                  let code = try? JSONDecoder().decode(ErrorBody.self, from: body).code,
                  (1...64).contains(code.utf8.count),
                  code.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) || $0 == 95 }) else {
                return nil
            }
            return code
        }
    }
}
