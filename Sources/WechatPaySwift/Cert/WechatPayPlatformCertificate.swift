import Foundation
import X509

/// Failures contain no certificate material, merchant keys, response bodies, or signatures.
public enum WechatPayPlatformCertificateError: Error, Equatable, Sendable {
    case invalidCertificate
    case invalidSerialNumber
    case serialNumberMismatch
    case invalidValidity
    case certificateNotCurrentlyValid
    case unknownSerialNumber
    case refreshUnavailable
    case refreshThrottled
    case refreshFailed
    case persistenceFailed
    case missingSignatureHeaders
    case invalidSignature
    case invalidResponse
    case invalidEncryptedCertificate
    case certificateMetadataMismatch
    case invalidPublicKey
    case unknownPublicKeyID
}

/// An X.509 certificate parsed by Swift Certificates. Parsing is not a source of trust:
/// callers must supply trusted configuration or use the authenticated downloader below.
public struct WechatPayPlatformCertificate: Sendable {
    public let serialNumber: String
    public let notValidBefore: Date
    public let notValidAfter: Date
    public let pem: String

    public init(pem: String, expectedSerialNumber: String? = nil) throws {
        guard pem.utf8.count <= 64 * 1024,
              let certificate = try? Certificate(pemEncoded: pem) else {
            throw WechatPayPlatformCertificateError.invalidCertificate
        }
        let serial = certificate.serialNumber.bytes.map { String(format: "%02X", $0) }.joined()
        self.serialNumber = try Self.normalizeSerialNumber(serial)
        if let expectedSerialNumber,
           try Self.normalizeSerialNumber(expectedSerialNumber) != self.serialNumber {
            throw WechatPayPlatformCertificateError.serialNumberMismatch
        }
        guard certificate.notValidBefore < certificate.notValidAfter else {
            throw WechatPayPlatformCertificateError.invalidValidity
        }
        self.notValidBefore = certificate.notValidBefore
        self.notValidAfter = certificate.notValidAfter
        guard let canonicalPEM = try? certificate.serializeAsPEM().pemString else {
            throw WechatPayPlatformCertificateError.invalidCertificate
        }
        self.pem = canonicalPEM
    }

    public func isValid(at date: Date) -> Bool {
        notValidBefore <= date && date < notValidAfter
    }

    public static func normalizeSerialNumber(_ value: String) throws -> String {
        guard !value.isEmpty, value.utf8.count <= 128,
              value.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else {
            throw WechatPayPlatformCertificateError.invalidSerialNumber
        }
        let normalized = value.uppercased().drop(while: { $0 == "0" })
        return normalized.isEmpty ? "0" : String(normalized)
    }
}

public protocol WechatPayPlatformCertificateProvider: Sendable {
    /// Return only the requested serial and require its X.509 validity at the provider's
    /// current clock. Implementations must never trust certificates supplied by a callback.
    func certificate(for serialNumber: String) async throws -> WechatPayPlatformCertificate
    func verificationKey(for identifier: String) async throws -> WechatPayVerificationKey
}

extension WechatPayPlatformCertificateProvider {
    public func verificationKey(for identifier: String) async throws -> WechatPayVerificationKey {
        .certificate(try await certificate(for: identifier))
    }
}

/// One instance belongs to one merchant. The application owns the channel/merchant
/// registry and persistent storage. Fetchers must return authenticated certificates.
public actor WechatPayPlatformCertificateStore: WechatPayPlatformCertificateProvider {
    public typealias Refresh = @Sendable () async throws -> [WechatPayPlatformCertificate]
    public typealias Clock = @Sendable () -> Date
    public typealias Persist = @Sendable ([WechatPayPlatformCertificate]) async throws -> Void

    private var certificates: [String: WechatPayPlatformCertificate]
    private let publicKeys: [String: TrustedWechatPublicKey]
    private let fetch: Refresh?
    private let clock: Clock
    private let minimumRefreshInterval: TimeInterval
    private let persist: Persist?
    private var lastRefreshAttempt: Date?
    private var pending: Task<[WechatPayPlatformCertificate], Error>?
    private var generation = 0

    public init(
        certificates: [WechatPayPlatformCertificate],
        refresh: Refresh? = nil,
        clock: @escaping Clock = { Date() },
        minimumRefreshInterval: TimeInterval = 60,
        persist: Persist? = nil,
        publicKeys: [TrustedWechatPublicKey] = []
    ) throws {
        guard minimumRefreshInterval.isFinite, minimumRefreshInterval >= 0,
              certificates.count <= 32, publicKeys.count <= 32 else {
            throw WechatPayPlatformCertificateError.invalidResponse
        }
        self.certificates = try Self.index(certificates)
        var trusted: [String: TrustedWechatPublicKey] = [:]
        for key in publicKeys {
            if let previous = trusted[key.id], previous.pem != key.pem {
                throw WechatPayPlatformCertificateError.invalidPublicKey
            }
            trusted[key.id] = key
        }
        self.publicKeys = trusted
        self.fetch = refresh
        self.clock = clock
        self.minimumRefreshInterval = minimumRefreshInterval
        self.persist = persist
    }

    public func snapshot() -> [WechatPayPlatformCertificate] {
        let now = clock()
        return certificates.values.filter { $0.notValidAfter > now }.sorted { $0.serialNumber < $1.serialNumber }
    }

    public func verificationKey(for identifier: String) async throws -> WechatPayVerificationKey {
        if identifier.hasPrefix("PUB_KEY_ID_") {
            let id = try TrustedWechatPublicKey.validateID(identifier)
            guard let key = publicKeys[id] else { throw WechatPayPlatformCertificateError.unknownPublicKeyID }
            return .publicKey(key)
        }
        return .certificate(try await certificate(for: identifier))
    }

    public func certificate(for serialNumber: String) async throws -> WechatPayPlatformCertificate {
        let serial = try WechatPayPlatformCertificate.normalizeSerialNumber(serialNumber)
        if let known = certificates[serial] {
            guard known.isValid(at: clock()) else {
                throw WechatPayPlatformCertificateError.certificateNotCurrentlyValid
            }
            return known
        }
        do {
            try await refresh()
        } catch {
            // Valid old certificates remain available even when a download or persistence fails.
            if let known = certificates[serial], known.isValid(at: clock()) { return known }
            throw error
        }
        guard let selected = certificates[serial] else {
            throw WechatPayPlatformCertificateError.unknownSerialNumber
        }
        guard selected.isValid(at: clock()) else {
            throw WechatPayPlatformCertificateError.certificateNotCurrentlyValid
        }
        return selected
    }

    /// Startup/periodic refresh uses the same single-flight and cooldown as an unknown serial.
    /// Omission from a new response never evicts a still-unexpired old certificate.
    public func refresh() async throws {
        if let task = pending {
            let id = generation
            try await finish(task, generation: id)
            return
        }
        guard let fetch else { throw WechatPayPlatformCertificateError.refreshUnavailable }
        let now = clock()
        if let previous = lastRefreshAttempt,
           now.timeIntervalSince(previous) < minimumRefreshInterval {
            throw WechatPayPlatformCertificateError.refreshThrottled
        }
        lastRefreshAttempt = now
        generation += 1
        let id = generation
        let old = certificates
        let persist = self.persist
        let task = Task<[WechatPayPlatformCertificate], Error> {
            let downloaded: [WechatPayPlatformCertificate]
            do { downloaded = try await fetch() }
            catch { throw WechatPayPlatformCertificateError.refreshFailed }
            guard !downloaded.isEmpty, downloaded.count <= 32 else {
                throw WechatPayPlatformCertificateError.invalidResponse
            }
            var merged = old.filter { $0.value.notValidAfter > now }
            for (serial, certificate) in try Self.index(downloaded) {
                // A different public key under an already trusted serial is a conflict, not rotation.
                if let previous = merged[serial], previous.pem != certificate.pem {
                    throw WechatPayPlatformCertificateError.serialNumberMismatch
                }
                if certificate.notValidAfter > now { merged[serial] = certificate }
            }
            guard merged.count <= 32 else { throw WechatPayPlatformCertificateError.invalidResponse }
            let result = merged.values.sorted { $0.serialNumber < $1.serialNumber }
            if let persist {
                do { try await persist(result) }
                catch { throw WechatPayPlatformCertificateError.persistenceFailed }
            }
            return result
        }
        pending = task
        try await finish(task, generation: id)
    }

    private func finish(_ task: Task<[WechatPayPlatformCertificate], Error>, generation id: Int) async throws {
        do {
            let loaded = try await task.value
            if generation == id {
                certificates = try Self.index(loaded)
                pending = nil
            }
        } catch {
            if generation == id { pending = nil }
            throw error
        }
    }

    private static func index(_ values: [WechatPayPlatformCertificate]) throws -> [String: WechatPayPlatformCertificate] {
        var result: [String: WechatPayPlatformCertificate] = [:]
        for certificate in values {
            if let previous = result[certificate.serialNumber], previous.pem != certificate.pem {
                throw WechatPayPlatformCertificateError.serialNumberMismatch
            }
            result[certificate.serialNumber] = certificate
        }
        return result
    }
}
