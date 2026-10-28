import XCTest
import Foundation
import Crypto
import AsyncHTTPClient
import NIOHTTP1
@testable import WechatPaySwift

/// Uses only generated, published test keys and an injected transport. No merchant network/DB/env.
final class PlatformCertificateTests: XCTestCase {
    let apiKey = "0123456789abcdef0123456789abcdef"
    let message = "{\"offline\":true}"
    let nonce = "notification-nonce"

    func fixture(_ name: String) throws -> String {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "pem", subdirectory: "Fixtures"))
        return try String(contentsOf: url)
    }
    func certificate(_ name: String) throws -> WechatPayPlatformCertificate {
        try WechatPayPlatformCertificate(pem: fixture("platform-" + name))
    }
    func clockDate() throws -> Date { try certificate("a").notValidBefore.addingTimeInterval(3600) }
    func timestamp() throws -> String { String(Int64(try clockDate().timeIntervalSince1970)) }
    func signature(_ key: String, timestamp: String? = nil, body: String? = nil) throws -> String {
        try XCTUnwrap(RSASigner.sign(
            text: "\(try timestamp ?? self.timestamp())\n\(nonce)\n\(body ?? message)\n",
            privateKeyPem: fixture("platform-" + key + ".key")))
    }
    func validator(_ certificates: [WechatPayPlatformCertificate], now: Date? = nil) throws -> WechatPaySignatureValidator {
        let fixed = try now ?? clockDate()
        let store = try WechatPayPlatformCertificateStore(certificates: certificates, clock: { fixed })
        return WechatPaySignatureValidator(certificateProvider: store, clock: { fixed })
    }
    func headers(_ envelope: WechatPayPlatformCertificateEnvelope) -> HTTPHeaders {
        ["Wechatpay-Serial": envelope.serialNumber, "Wechatpay-Timestamp": envelope.timestamp,
         "Wechatpay-Nonce": envelope.nonce, "Wechatpay-Signature": envelope.signature]
    }
    func envelope(
        _ certificates: [WechatPayPlatformCertificate], key: String = "a",
        edit: ((inout [[String: Any]]) -> Void)? = nil
    ) throws -> WechatPayPlatformCertificateEnvelope {
        let formatter = ISO8601DateFormatter()
        var entries = try certificates.enumerated().map { index, certificate -> [String: Any] in
            // These nonces and this key are fixed test-only data, never production material.
            let nonceText = String(format: "certnonce%03d", index)
            let sealed = try AES.GCM.seal(
                Data(certificate.pem.utf8), using: SymmetricKey(data: Data(apiKey.utf8)),
                nonce: AES.GCM.Nonce(data: Data(nonceText.utf8)), authenticating: Data("certificate".utf8))
            return ["serial_no": certificate.serialNumber,
                    "effective_time": formatter.string(from: certificate.notValidBefore),
                    "expire_time": formatter.string(from: certificate.notValidAfter),
                    "encrypt_certificate": ["algorithm": "AEAD_AES_256_GCM", "nonce": nonceText,
                                             "associated_data": "certificate",
                                             "ciphertext": (sealed.ciphertext + sealed.tag).base64EncodedString()]]
        }
        edit?(&entries)
        let body = try JSONSerialization.data(withJSONObject: ["data": entries], options: [.sortedKeys])
        let bodyString = try XCTUnwrap(String(data: body, encoding: .utf8))
        let stamp = try timestamp()
        return try WechatPayPlatformCertificateEnvelope(
            body: body, serialNumber: certificate(key).serialNumber,
            timestamp: stamp, nonce: nonce, signature: signature(key, timestamp: stamp, body: bodyString))
    }
    func downloader(now: Date? = nil, key: String? = nil) throws -> WechatPayPlatformCertificateDownloader {
        let fixed = try now ?? clockDate()
        return try WechatPayPlatformCertificateDownloader(
            apiV3Secret: key ?? apiKey, merchantCertificateContent: fixture("platform-a.key"),
            merchantID: "offline-test-merchant", merchantCertificateSerialNumber: "merchant-test-serial", clock: { fixed })
    }

    func testX509SerialAndValidityAreParsedAndPEMIsCanonical() throws {
        let a = try certificate("a")
        XCTAssertEqual(a.serialNumber, "A1")
        XCTAssertTrue(a.isValid(at: try clockDate()))
        XCTAssertEqual(try WechatPayPlatformCertificate(pem: a.pem.replacingOccurrences(of: "\n", with: "\r\n"), expectedSerialNumber: "00a1").pem, a.pem)
        XCTAssertThrowsError(try WechatPayPlatformCertificate(pem: a.pem, expectedSerialNumber: "B2"))
        XCTAssertThrowsError(try WechatPayPlatformCertificate(pem: "not a certificate"))
    }

    func testNewAndOldRealSignaturesCoexist() async throws {
        let v = try validator([certificate("a"), certificate("b")])
        let a = try await v.verify(serialNumber: "A1", timestamp: timestamp(), nonce: nonce, body: message, signature: signature("a"))
        let b = try await v.verify(serialNumber: "b2", timestamp: timestamp(), nonce: nonce, body: message, signature: signature("b"))
        XCTAssertTrue(a); XCTAssertTrue(b)
    }

    func testWrongSerialAndForgedOrMalformedSignaturesAreRejected() async throws {
        let v = try validator([certificate("a"), certificate("b")])
        let wrong = try await v.verify(serialNumber: "A1", timestamp: timestamp(), nonce: nonce, body: message, signature: signature("b"))
        let forged = try await v.verify(serialNumber: "B2", timestamp: timestamp(), nonce: nonce, body: message + "!", signature: signature("b"))
        let malformed = try await v.verify(serialNumber: "A1", timestamp: timestamp(), nonce: nonce, body: message, signature: "bad-base64!")
        XCTAssertFalse(wrong); XCTAssertFalse(forged); XCTAssertFalse(malformed)
    }

    func testUnknownSerialNeverTriesTheOldCertificate() async throws {
        let v = try validator([certificate("a")])
        do {
            _ = try await v.verify(serialNumber: "DEAD", timestamp: timestamp(), nonce: nonce, body: message, signature: signature("a"))
            XCTFail("unknown serial accepted an old-key signature")
        } catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .refreshUnavailable) }
    }

    func testFutureAndExpiredCertificateCannotVerifyCurrentResponse() async throws {
        let a = try certificate("a")
        for date in [a.notValidBefore.addingTimeInterval(-1), a.notValidAfter] {
            let v = try validator([a], now: date)
            do {
                _ = try await v.verify(serialNumber: "A1", timestamp: String(Int64(date.timeIntervalSince1970)), nonce: nonce, body: message, signature: signature("a", timestamp: String(Int64(date.timeIntervalSince1970))))
                XCTFail("certificate outside its validity was used")
            } catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .certificateNotCurrentlyValid) }
        }
    }

    func testAPIResponseUsesItsSerialAndRequiresAllSingleHeaders() async throws {
        let v = try validator([certificate("a"), certificate("b")])
        let e = try envelope([certificate("a"), certificate("b")], key: "b")
        let body = String(decoding: e.body, as: UTF8.self)
        try await v.validate(response: HTTPClientResponse(headers: headers(e)), body: body)
        for field in ["Wechatpay-Serial", "Wechatpay-Timestamp", "Wechatpay-Nonce", "Wechatpay-Signature"] {
            var h = headers(e); h.remove(name: field)
            do { try await v.validate(response: HTTPClientResponse(headers: h), body: body); XCTFail("missing header accepted") }
            catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .missingSignatureHeaders) }
        }
        var duplicated = headers(e); duplicated.add(name: "Wechatpay-Serial", value: "A1")
        do { try await v.validate(response: HTTPClientResponse(headers: duplicated), body: body); XCTFail("ambiguous serial accepted") }
        catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .missingSignatureHeaders) }
    }

    func testUnknownSerialRefreshIsSingleFlightAndRetainsOldCertificate() async throws {
        let a = try certificate("a"), b = try certificate("b"), now = try clockDate()
        let calls = CallCounter()
        let store = try WechatPayPlatformCertificateStore(certificates: [a], refresh: {
            await calls.increment()
            try await Task.sleep(nanoseconds: 30_000_000)
            return [b]
        }, clock: { now })
        try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<24 { group.addTask { try await store.certificate(for: "B2").serialNumber } }
            for try await serial in group { XCTAssertEqual(serial, "B2") }
        }
        let count = await calls.value
        XCTAssertEqual(count, 1)
        let oldSerial = try await store.certificate(for: "A1").serialNumber
        let snapshot = await store.snapshot().map(\.serialNumber)
        XCTAssertEqual(oldSerial, "A1")
        XCTAssertEqual(snapshot, ["A1", "B2"])
    }

    func testFailureIsBoundedAndLeavesOldCertificateAvailable() async throws {
        let a = try certificate("a"), now = try clockDate(), calls = CallCounter()
        let store = try WechatPayPlatformCertificateStore(certificates: [a], refresh: {
            await calls.increment(); throw TestFailure.expected
        }, clock: { now })
        do { _ = try await store.certificate(for: "B2"); XCTFail("failed refresh accepted") }
        catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .refreshFailed) }
        do { _ = try await store.certificate(for: "C3"); XCTFail("cooldown bypassed") }
        catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .refreshThrottled) }
        let old = try await store.certificate(for: "A1"), count = await calls.value
        XCTAssertEqual(old.serialNumber, "A1"); XCTAssertEqual(count, 1)
    }

    func testPersistenceFailureDoesNotInstallNewCertificate() async throws {
        let a = try certificate("a"), b = try certificate("b"), now = try clockDate()
        let response = try envelope([a, b]), verifier = try downloader(), cache = FailingEnvelopeCache()
        let store = try WechatPayPlatformCertificateStore(certificates: [a], refresh: {
            let bundle = try verifier.verifyCachedEnvelopeBundle(response)
            try await cache.save(bundle.envelope)
            return bundle.certificates
        }, clock: { now })
        do { try await store.refresh(); XCTFail("persistence error ignored") }
        catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .refreshFailed) }
        let snapshot = await store.snapshot().map(\.serialNumber)
        let attempts = await cache.attempts
        XCTAssertEqual(snapshot, ["A1"])
        XCTAssertEqual(attempts, 1)
    }

    func testExplicitRefreshRetainsStillValidOldCertificatesAndRejectsSerialConflict() async throws {
        let a = try certificate("a"), b = try certificate("b"), conflict = try certificate("conflict"), now = try clockDate()
        let store = try WechatPayPlatformCertificateStore(certificates: [a], refresh: { [b] }, clock: { now })
        try await store.refresh()
        let snapshot = await store.snapshot().map(\.serialNumber)
        XCTAssertEqual(snapshot, ["A1", "B2"])
        let conflicting = try WechatPayPlatformCertificateStore(certificates: [a], refresh: { [conflict] }, clock: { now })
        do { try await conflicting.refresh(); XCTFail("different certificate reused a trusted serial") }
        catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .serialNumberMismatch) }
        let preservedPEM = try await conflicting.certificate(for: "A1").pem
        XCTAssertEqual(preservedPEM, a.pem)
    }

    func testEncryptedEnvelopeCanBeReloadedAndReverifiedAfterRestart() throws {
        let e = try envelope([certificate("a"), certificate("b")])
        let encoded = try JSONEncoder().encode(e)
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("BEGIN CERTIFICATE"))
        let reloaded = try JSONDecoder().decode(WechatPayPlatformCertificateEnvelope.self, from: encoded)
        XCTAssertEqual(try downloader().verifyCachedEnvelope(reloaded).map(\.serialNumber), ["A1", "B2"])
        XCTAssertEqual(try downloader().verifyCachedEnvelopeBundle(reloaded).envelope.body, e.body)
    }

    func testCachedOldSignerExpiryDoesNotDiscardStillValidNewCertificate() async throws {
        let a = try certificate("a"), b = try certificate("b")
        let e = try envelope([a, b])
        let later = a.notValidAfter.addingTimeInterval(1)
        let reloaded = try downloader(now: later).verifyCachedEnvelope(e)
        let store = try WechatPayPlatformCertificateStore(certificates: reloaded, clock: { later })
        let snapshot = await store.snapshot().map(\.serialNumber)
        let current = try await store.certificate(for: "B2").serialNumber
        XCTAssertEqual(snapshot, ["B2"])
        XCTAssertEqual(current, "B2")
        do { _ = try await store.certificate(for: "A1"); XCTFail("expired signer used for a current message") }
        catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .certificateNotCurrentlyValid) }
    }

    func testWrongKeyCiphertextSignatureAndMalformedCertificateCannotBeCached() throws {
        let e = try envelope([certificate("a"), certificate("b")])
        XCTAssertThrowsError(try downloader(key: "fedcba9876543210fedcba9876543210").verifyCachedEnvelope(e))
        let badSignature = WechatPayPlatformCertificateEnvelope(body: e.body, serialNumber: e.serialNumber, timestamp: e.timestamp, nonce: e.nonce, signature: "not-base64!")
        XCTAssertThrowsError(try downloader().verifyCachedEnvelope(badSignature))
        var bytes = e.body; bytes[bytes.count / 2] ^= 1
        let tampered = WechatPayPlatformCertificateEnvelope(body: bytes, serialNumber: e.serialNumber, timestamp: e.timestamp, nonce: e.nonce, signature: e.signature)
        XCTAssertThrowsError(try downloader().verifyCachedEnvelope(tampered))
    }

    func testPayloadSerialDatesAndDuplicateEntriesMustMatchX509() throws {
        let a = try certificate("a")
        for field in ["serial_no", "effective_time", "expire_time"] {
            let bad = try envelope([a], edit: { entries in
                entries[0][field] = field == "serial_no" ? "B2" : "2020-01-01T00:00:00Z"
            })
            XCTAssertThrowsError(try downloader().verifyCachedEnvelope(bad))
        }
        XCTAssertThrowsError(try downloader().verifyCachedEnvelope(envelope([a, a])))
    }

    func testOnlyCertificateDownloaderBootstrapsAnUnknownNewSerial() async throws {
        let a = try certificate("a"), b = try certificate("b"), now = try clockDate()
        let e = try envelope([a, b], key: "b")
        let responseHeaders = headers(e)
        let d = try WechatPayPlatformCertificateDownloader(
            apiV3Secret: apiKey, merchantCertificateContent: fixture("platform-a.key"), merchantID: "offline-merchant",
            merchantCertificateSerialNumber: "merchant-test-serial", clock: { now }, testTransport: { request in
                XCTAssertEqual(request.url, "https://api.mch.weixin.qq.com/v3/certificates")
                XCTAssertEqual(request.method, .GET)
                XCTAssertNotNil(request.headers.first(name: "Authorization"))
                return .init(status: 200, headers: responseHeaders, body: e.body)
            })
        let bundle = try await d.download()
        XCTAssertEqual(bundle.certificates.map(\.serialNumber), ["A1", "B2"])
        let oldOnly = try validator([a])
        do { try await oldOnly.validate(response: HTTPClientResponse(headers: responseHeaders), body: String(decoding: e.body, as: UTF8.self)); XCTFail("ordinary API used certificate bootstrap bypass") }
        catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .refreshUnavailable) }
    }

    func testDownloadedResponseMustBeFreshWhileAuthenticatedCacheMayBeHistorical() async throws {
        let e = try envelope([certificate("a"), certificate("b")]), later = try clockDate().addingTimeInterval(301)
        let responseHeaders = headers(e)
        let d = try WechatPayPlatformCertificateDownloader(
            apiV3Secret: apiKey, merchantCertificateContent: fixture("platform-a.key"), merchantID: "offline-merchant",
            merchantCertificateSerialNumber: "merchant-test-serial", clock: { later }, testTransport: { _ in
                .init(status: 200, headers: responseHeaders, body: e.body)
            })
        do { _ = try await d.download(); XCTFail("stale network response accepted") }
        catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .invalidResponse) }
        XCTAssertEqual(try d.verifyCachedEnvelope(e).map(\.serialNumber), ["A1", "B2"])
    }

    func trustedPublicKey(_ name: String = "b", id: String = "PUB_KEY_ID_OFFLINE_B") throws -> TrustedWechatPublicKey {
        try TrustedWechatPublicKey(id: id, pem: fixture("platform-" + name + ".public"))
    }

    func publicKeyEnvelope(id: String = "PUB_KEY_ID_OFFLINE_B") throws -> WechatPayPlatformCertificateEnvelope {
        let original = try envelope([certificate("a"), certificate("b")], key: "b")
        return WechatPayPlatformCertificateEnvelope(
            body: original.body, serialNumber: id, timestamp: original.timestamp,
            nonce: original.nonce, signature: original.signature)
    }

    func testExplicitPublicKeyWorksWithoutAnyCertificateSeedOrFetch() async throws {
        let key = try trustedPublicKey(), now = try clockDate(), calls = CallCounter()
        let store = try WechatPayPlatformCertificateStore(certificates: [], refresh: {
            await calls.increment(); throw TestFailure.expected
        }, clock: { now }, publicKeys: [key])
        let v = WechatPaySignatureValidator(certificateProvider: store, clock: { now })
        let valid = try await v.verify(serialNumber: key.id, timestamp: timestamp(), nonce: nonce, body: message, signature: signature("b"))
        XCTAssertTrue(valid)
        let e = try publicKeyEnvelope()
        try await v.validate(response: HTTPClientResponse(headers: headers(e)), body: String(decoding: e.body, as: UTF8.self))
        let count = await calls.value
        XCTAssertEqual(count, 0)
    }

    func testUnknownPublicKeyAndWrongPublicSignatureFailWithoutCertificateDownload() async throws {
        let key = try trustedPublicKey(), now = try clockDate(), calls = CallCounter()
        let store = try WechatPayPlatformCertificateStore(certificates: [certificate("a")], refresh: {
            await calls.increment(); return []
        }, clock: { now }, publicKeys: [key])
        let v = WechatPaySignatureValidator(certificateProvider: store, clock: { now })
        do {
            _ = try await v.verify(serialNumber: "PUB_KEY_ID_UNKNOWN", timestamp: timestamp(), nonce: nonce, body: message, signature: signature("a"))
            XCTFail("unconfigured public key id accepted")
        } catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .unknownPublicKeyID) }
        let forged = try await v.verify(serialNumber: key.id, timestamp: timestamp(), nonce: nonce, body: message, signature: signature("a"))
        XCTAssertFalse(forged)
        let count = await calls.value
        XCTAssertEqual(count, 0)
    }

    func testMalformedOrPrivatePEMAndInvalidPublicKeyIDsAreRejected() throws {
        for id in ["B2", "PUB_KEY_ID_", "PUB_KEY_ID_bad value", "PUB_KEY_ID_bad/route"] {
            XCTAssertThrowsError(try trustedPublicKey(id: id))
        }
        XCTAssertThrowsError(try TrustedWechatPublicKey(id: "PUB_KEY_ID_OFFLINE_B", pem: "not a key"))
        XCTAssertThrowsError(try TrustedWechatPublicKey(id: "PUB_KEY_ID_OFFLINE_B", pem: fixture("platform-b.key")))
        XCTAssertThrowsError(try TrustedWechatPublicKey(id: "PUB_KEY_ID_OFFLINE_B", pem: certificate("b").pem))
    }

    func testCertificatesAndPublicKeyCoexistDuringMigration() async throws {
        let a = try certificate("a"), b = try certificate("b"), now = try clockDate(), key = try trustedPublicKey()
        let store = try WechatPayPlatformCertificateStore(certificates: [a, b], clock: { now }, publicKeys: [key])
        let v = WechatPaySignatureValidator(certificateProvider: store, clock: { now })
        for (id, signingKey) in [("A1", "a"), ("B2", "b"), (key.id, "b")] {
            let valid = try await v.verify(serialNumber: id, timestamp: timestamp(), nonce: nonce, body: message, signature: signature(signingKey))
            XCTAssertTrue(valid)
        }
    }

    func testConfiguredPublicKeyCanAuthenticateCertificateDownloadAndCache() async throws {
        let key = try trustedPublicKey(), now = try clockDate(), e = try publicKeyEnvelope()
        let responseHeaders = headers(e)
        let d = try WechatPayPlatformCertificateDownloader(
            apiV3Secret: apiKey, merchantCertificateContent: fixture("platform-a.key"), merchantID: "offline-merchant",
            merchantCertificateSerialNumber: "merchant-test-serial", clock: { now }, trustedPublicKeys: [key], testTransport: { _ in
                .init(status: 200, headers: responseHeaders, body: e.body)
            })
        let bundle = try await d.download()
        XCTAssertEqual(bundle.certificates.map(\.serialNumber), ["A1", "B2"])
        let reloaded = try JSONDecoder().decode(WechatPayPlatformCertificateEnvelope.self, from: JSONEncoder().encode(bundle.envelope))
        XCTAssertEqual(try d.verifyCachedEnvelope(reloaded).map(\.serialNumber), ["A1", "B2"])
    }

    func testUnconfiguredOrChangedPublicKeyCannotBootstrapFromCertificatePayload() throws {
        let e = try publicKeyEnvelope(), now = try clockDate()
        XCTAssertThrowsError(try downloader().verifyCachedEnvelope(e))
        let wrong = try trustedPublicKey("a")
        let d = try WechatPayPlatformCertificateDownloader(
            apiV3Secret: apiKey, merchantCertificateContent: fixture("platform-a.key"), merchantID: "offline-merchant",
            merchantCertificateSerialNumber: "merchant-test-serial", clock: { now }, trustedPublicKeys: [wrong])
        XCTAssertThrowsError(try d.verifyCachedEnvelope(e))
    }

    func testProviderCannotSubstituteDifferentSerialOrPublicKeyID() async throws {
        let a = try certificate("a")
        let now = try clockDate()
        let v = WechatPaySignatureValidator(certificateProvider: SubstitutingProvider(certificate: a), clock: { now })
        for id in ["B2", "PUB_KEY_ID_UNKNOWN"] {
            do {
                _ = try await v.verify(serialNumber: id, timestamp: timestamp(), nonce: nonce, body: message, signature: signature("a"))
                XCTFail("provider selected a different identity")
            } catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError,
                                     id.hasPrefix("PUB_KEY_ID_") ? .unknownPublicKeyID : .serialNumberMismatch) }
        }
    }

    func testStaleFutureAndMalformedTimestampsRejectBeforeLookupOrFetch() async throws {
        let now = try clockDate(), calls = CallCounter(), lookups = CallCounter()
        let a = try certificate("a")
        let store = try WechatPayPlatformCertificateStore(certificates: [a], refresh: {
            await calls.increment(); return [a]
        }, clock: { now })
        let provider = CountingProvider(store: store, lookups: lookups)
        let v = WechatPaySignatureValidator(certificateProvider: provider, clock: { now })
        let seconds = Int64(now.timeIntervalSince1970)
        let invalid = ["1", "abc", "", "0", "-1", "+123", " 123", "123 ", "1.0", "1e9",
                       "9223372036854775808", "999999999999999999999999999999", "١٢٣"]
            + [-301, -300, 300, 301].map { String(seconds + Int64($0)) }
        for stamp in invalid {
            let signed = try signature("a", timestamp: stamp)
            do {
                _ = try await v.verify(serialNumber: "B2", timestamp: stamp, nonce: nonce, body: message, signature: signed)
                XCTFail("invalid timestamp accepted")
            } catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .invalidTimestamp) }
            let h: HTTPHeaders = ["Wechatpay-Serial": "B2", "Wechatpay-Timestamp": stamp,
                                  "Wechatpay-Nonce": nonce, "Wechatpay-Signature": signed]
            do { try await v.validate(response: HTTPClientResponse(headers: h), body: message); XCTFail("invalid API timestamp accepted") }
            catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError,
                                   stamp.isEmpty ? .missingSignatureHeaders : .invalidTimestamp) }
        }
        let lookupCount = await lookups.value, fetchCount = await calls.value
        XCTAssertEqual(lookupCount, 0); XCTAssertEqual(fetchCount, 0)
    }

    func testTimestampInsideFiveMinuteBoundaryUsesInjectedClock() async throws {
        let now = try clockDate(), v = try validator([certificate("a")])
        for delta in [-299, 0, 299] {
            let stamp = String(Int64(now.timeIntervalSince1970) + Int64(delta))
            let valid = try await v.verify(serialNumber: "A1", timestamp: stamp, nonce: nonce,
                                           body: message, signature: signature("a", timestamp: stamp))
            XCTAssertTrue(valid)
        }
    }

    func testMalformedSignatureRejectsBeforeLookupOrFetch() async throws {
        let now = try clockDate(), calls = CallCounter(), lookups = CallCounter(), a = try certificate("a")
        let store = try WechatPayPlatformCertificateStore(certificates: [a], refresh: {
            await calls.increment(); return [a]
        }, clock: { now })
        let v = WechatPaySignatureValidator(certificateProvider: CountingProvider(store: store, lookups: lookups), clock: { now })
        for signature in ["", "bad-base64!"] {
            let valid = try await v.verify(serialNumber: "B2", timestamp: timestamp(), nonce: nonce, body: message, signature: signature)
            XCTAssertFalse(valid)
        }
        let lookupCount = await lookups.value, fetchCount = await calls.value
        XCTAssertEqual(lookupCount, 0); XCTAssertEqual(fetchCount, 0)
    }

    func testCooldownExpiresAndAllowsSecondRefresh() async throws {
        let clock = try MutableClock(clockDate()), calls = CallCounter(), a = try certificate("a")
        let store = try WechatPayPlatformCertificateStore(certificates: [a], refresh: {
            await calls.increment(); return [a]
        }, clock: { clock.now })
        try await store.refresh()
        clock.advance(59)
        do { try await store.refresh(); XCTFail("cooldown ignored") }
        catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .refreshThrottled) }
        clock.advance(2)
        try await store.refresh()
        let count = await calls.value
        XCTAssertEqual(count, 2)
    }

    func testDefaultProviderRejectsPublicKeyIDWithoutCertificateLookup() async throws {
        let now = try clockDate(), calls = CallCounter(), a = try certificate("a")
        let store = try WechatPayPlatformCertificateStore(certificates: [a], refresh: {
            await calls.increment(); return [a]
        }, clock: { now })
        let lookups = CallCounter(), provider = CountingProvider(store: store, lookups: lookups)
        do { _ = try await provider.verificationKey(for: "PUB_KEY_ID_UNKNOWN"); XCTFail("default provider accepted a public key id") }
        catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .unknownPublicKeyID) }
        let lookupCount = await lookups.value, fetchCount = await calls.value
        XCTAssertEqual(lookupCount, 0); XCTAssertEqual(fetchCount, 0)
    }

    func client(key: String? = nil) throws -> WechatPay {
        let now = try clockDate()
        let store = try WechatPayPlatformCertificateStore(certificates: [], clock: { now }, publicKeys: [trustedPublicKey()])
        return try WechatPay(apiV3Secret: key ?? apiKey, certificateContent: fixture("platform-a.key"),
                             mchid: "offline-test-merchant", serialNo: "offline-test-serial",
                             certificateProvider: store, clock: { now })
    }

    func testWechatPayNotificationEntryUsesProviderClockAndPublicKey() async throws {
        let c = try client()
        let valid = try await c.verifyNotification(serialNumber: "PUB_KEY_ID_OFFLINE_B", timestamp: timestamp(),
                                                  nonce: nonce, body: message, signature: signature("b"))
        XCTAssertTrue(valid)
        do {
            _ = try await c.verifyNotification(serialNumber: "PUB_KEY_ID_OFFLINE_B", timestamp: "1",
                                              nonce: nonce, body: message, signature: signature("b", timestamp: "1"))
            XCTFail("notification entry ignored clock")
        } catch { XCTAssertEqual(error as? WechatPayPlatformCertificateError, .invalidTimestamp) }
    }

    func encryptedResource(_ plaintext: Data) throws -> String {
        let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: Data(apiKey.utf8)),
                                     nonce: AES.GCM.Nonce(data: Data("resource0001".utf8)), authenticating: Data("resource".utf8))
        return (sealed.ciphertext + sealed.tag).base64EncodedString()
    }

    func notification(ciphertext: String, resourceNonce: String = "resource0001") -> WechatPay.H5API.PayNotification {
        .init(id: "offline-notification", createTime: Date(timeIntervalSince1970: 1), resourceType: "encrypt-resource",
              eventType: .transactionSuccess, summary: "offline",
              resource: .init(originalType: "transaction", algorithm: "AEAD_AES_256_GCM", ciphertext: ciphertext,
                              associatedData: "resource", nonce: resourceNonce))
    }

    func testMalformedNotificationResourceThrowsTypedErrorsWithoutCrashing() throws {
        let api = WechatPay.H5API(wechatPay: try client())
        let encrypted = try encryptedResource(Data(message.utf8))
        let cases: [(String, String, WechatPayDecryptionError)] = [
            ("bad-base64!", "resource0001", .invalidCiphertext),
            (Data(repeating: 0, count: 15).base64EncodedString(), "resource0001", .invalidCiphertext),
            (encrypted, "short", .invalidNonce), (encrypted, "resource0001too-long", .invalidNonce),
            (encrypted, "resource0002", .authenticationFailed),
            (try encryptedResource(Data([0xFF, 0xFE])), "resource0001", .invalidPlaintext)
        ]
        for (ciphertext, resourceNonce, expected) in cases {
            XCTAssertThrowsError(try api.decodeNotification(notification(ciphertext: ciphertext, resourceNonce: resourceNonce)) as [String: Bool]) {
                XCTAssertEqual($0 as? WechatPayDecryptionError, expected)
            }
        }
        let valid: [String: Bool] = try api.decodeNotification(notification(ciphertext: encrypted))
        XCTAssertEqual(valid, ["offline": true])
        let badKeyAPI = WechatPay.H5API(wechatPay: try client(key: "short"))
        XCTAssertThrowsError(try badKeyAPI.decodeNotification(notification(ciphertext: encrypted)) as [String: Bool]) {
            XCTAssertEqual($0 as? WechatPayDecryptionError, .invalidAPIv3Key)
        }
    }

    func testLegacyValidatorPublicPEMAndMalformedSignatureDoNotCrash() throws {
        let legacy = try WechatPaySignatureValidator(wxCertContent: fixture("platform-b.public"))
        XCTAssertFalse(try legacy.verify(timestamp: timestamp(), nonce: nonce, body: message, signature: signature("b")))
        let certificateValidator = try WechatPaySignatureValidator(wxCertContent: certificate("b").pem)
        XCTAssertFalse(try certificateValidator.verify(timestamp: timestamp(), nonce: nonce, body: message, signature: "bad-base64!"))
    }

    func testPublicKeyAcceptsSPKIAndExplicitlyRejectsPKCS1() throws {
        XCTAssertNoThrow(try trustedPublicKey())
        XCTAssertThrowsError(try TrustedWechatPublicKey(id: "PUB_KEY_ID_OFFLINE_B", pem: fixture("platform-b.pkcs1.public"))) {
            XCTAssertEqual($0 as? WechatPayPlatformCertificateError, .invalidPublicKey)
        }
    }

}

private enum TestFailure: Error { case expected }
private actor CallCounter {
    private(set) var value = 0
    func increment() { value += 1 }
}

private actor FailingEnvelopeCache {
    private(set) var attempts = 0
    func save(_ envelope: WechatPayPlatformCertificateEnvelope) throws {
        attempts += 1
        throw TestFailure.expected
    }
}

private struct CountingProvider: WechatPayPlatformCertificateProvider {
    let store: WechatPayPlatformCertificateStore
    let lookups: CallCounter
    func certificate(for serialNumber: String) async throws -> WechatPayPlatformCertificate {
        await lookups.increment()
        return try await store.certificate(for: serialNumber)
    }
}

private final class MutableClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date
    init(_ value: Date) { self.value = value }
    var now: Date {
        lock.lock(); defer { lock.unlock() }
        return value
    }
    func advance(_ interval: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        value = value.addingTimeInterval(interval)
    }
}

private struct SubstitutingProvider: WechatPayPlatformCertificateProvider {
    let certificate: WechatPayPlatformCertificate
    func certificate(for serialNumber: String) async throws -> WechatPayPlatformCertificate { certificate }
}
