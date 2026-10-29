//
//  RefundModels.swift
//  Field names follow the APIv3 domestic refund documentation.
//

import Foundation

extension WechatPay.RefundAPI {
    public struct CreateRefundRequest: Codable, Equatable, Sendable {
        public struct Amount: Codable, Equatable, Sendable {
            /// Refund amount in minor units (fen).
            public let refund: Int64
            /// Original order total in minor units (fen).
            public let total: Int64
            public let currency: String

            public init(refund: Int64, total: Int64, currency: String) {
                self.refund = refund
                self.total = total
                self.currency = currency
            }
        }

        public let transactionID: String?
        public let outTradeNo: String?
        public let outRefundNo: String
        public let reason: String?
        public let notifyURL: String?
        public let amount: Amount

        public init(transactionID: String? = nil, outTradeNo: String? = nil, outRefundNo: String,
                    reason: String? = nil, notifyURL: String? = nil, amount: Amount) {
            self.transactionID = transactionID
            self.outTradeNo = outTradeNo
            self.outRefundNo = outRefundNo
            self.reason = reason
            self.notifyURL = notifyURL
            self.amount = amount
        }

        private enum CodingKeys: String, CodingKey {
            case transactionID = "transaction_id"
            case outTradeNo = "out_trade_no"
            case outRefundNo = "out_refund_no"
            case reason
            case notifyURL = "notify_url"
            case amount
        }

        /// Deterministic JSON (sorted keys, absent optionals omitted).
        public func encodedBody() throws -> Data {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            return try encoder.encode(self)
        }

        /// Restricted to characters that need no URL escaping so the same number can always be queried.
        public static func isValidOutRefundNo(_ value: String) -> Bool {
            (1...64).contains(value.utf8.count) && value.utf8.allSatisfy {
                (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 95 || $0 == 45
            }
        }

        /// Local preflight; a request that fails it is never sent.
        public var isValid: Bool {
            let transaction = transactionID.map { !$0.isEmpty } ?? false
            let trade = outTradeNo.map { !$0.isEmpty } ?? false
            guard transaction != trade, Self.isValidOutRefundNo(outRefundNo) else { return false }
            if let transactionID, transactionID.utf8.count > 32 { return false }
            if let outTradeNo, outTradeNo.utf8.count > 32 { return false }
            if let reason, reason.isEmpty || reason.count > 80 { return false }
            if let notifyURL {
                guard notifyURL.utf8.count <= 256, let url = URL(string: notifyURL), url.scheme == "https",
                      url.host?.isEmpty == false, url.query == nil, url.fragment == nil, url.user == nil else {
                    return false
                }
            }
            return amount.refund > 0 && amount.total > 0 && amount.refund <= amount.total && amount.currency == "CNY"
        }
    }

    /// Refund resource returned by create and query.
    public struct Refund: Codable, Equatable, Sendable {
        public enum Status: String, Codable, Sendable {
            case success = "SUCCESS"
            case closed = "CLOSED"
            case processing = "PROCESSING"
            case abnormal = "ABNORMAL"
        }

        public struct Amount: Codable, Equatable, Sendable {
            public let total: Int64
            public let refund: Int64
            public let payerTotal: Int64?
            public let payerRefund: Int64?
            public let settlementRefund: Int64?
            public let settlementTotal: Int64?
            public let discountRefund: Int64?
            public let currency: String
            public let refundFee: Int64?

            private enum CodingKeys: String, CodingKey {
                case total
                case refund
                case payerTotal = "payer_total"
                case payerRefund = "payer_refund"
                case settlementRefund = "settlement_refund"
                case settlementTotal = "settlement_total"
                case discountRefund = "discount_refund"
                case currency
                case refundFee = "refund_fee"
            }
        }

        public let refundID: String
        public let outRefundNo: String
        public let transactionID: String
        public let outTradeNo: String
        public let channel: String?
        public let userReceivedAccount: String?
        public let successTime: String?
        public let createTime: String?
        public let status: Status
        public let fundsAccount: String?
        public let amount: Amount

        private enum CodingKeys: String, CodingKey {
            case refundID = "refund_id"
            case outRefundNo = "out_refund_no"
            case transactionID = "transaction_id"
            case outTradeNo = "out_trade_no"
            case channel
            case userReceivedAccount = "user_received_account"
            case successTime = "success_time"
            case createTime = "create_time"
            case status
            case fundsAccount = "funds_account"
            case amount
        }
    }

    /// Decrypted `resource` of a REFUND.SUCCESS / REFUND.CLOSED / REFUND.ABNORMAL notification.
    /// It contains no currency field; callers that must match currency need a refund query.
    public struct RefundNotification: Codable, Equatable, Sendable {
        public enum Status: String, Codable, Sendable {
            case success = "SUCCESS"
            case closed = "CLOSE"
            case abnormal = "ABNORMAL"
        }

        public struct Amount: Codable, Equatable, Sendable {
            public let total: Int64
            public let refund: Int64
            public let payerTotal: Int64?
            public let payerRefund: Int64?
            public let currency: String?

            private enum CodingKeys: String, CodingKey {
                case total
                case refund
                case payerTotal = "payer_total"
                case payerRefund = "payer_refund"
                case currency
            }
        }

        public let mchid: String
        public let transactionID: String
        public let outTradeNo: String
        public let refundID: String
        public let outRefundNo: String
        public let refundStatus: Status
        public let successTime: String?
        public let userReceivedAccount: String?
        public let amount: Amount

        private enum CodingKeys: String, CodingKey {
            case mchid
            case transactionID = "transaction_id"
            case outTradeNo = "out_trade_no"
            case refundID = "refund_id"
            case outRefundNo = "out_refund_no"
            case refundStatus = "refund_status"
            case successTime = "success_time"
            case userReceivedAccount = "user_received_account"
            case amount
        }
    }
}
