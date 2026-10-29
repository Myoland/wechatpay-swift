import XCTest
import Foundation
import JWTKit
import AsyncHTTPClient
@testable import WechatPaySwift

final class RequestURLFailureTests: XCTestCase {
    private actor BodyReads {
        var count = 0
        func next() -> UInt8? { count += 1; return nil }
    }

    private struct CountingBody: AsyncSequence, Sendable {
        typealias Element = UInt8
        let reads: BodyReads
        struct AsyncIterator: AsyncIteratorProtocol {
            let reads: BodyReads
            mutating func next() async throws -> UInt8? { await reads.next() }
        }
        func makeAsyncIterator() -> AsyncIterator { AsyncIterator(reads: reads) }
    }

    private func fixture(_ name: String) throws -> String {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "pem", subdirectory: "Fixtures"))
        return try String(contentsOf: url, encoding: .utf8)
    }

    private func verify(_ signature: String, message: String) throws -> Bool {
        let key = try RSAKey.public(pem: fixture("test-merchant.public"))
        return try JWTSigner.rs256(key: key).algorithm.verify(
            try XCTUnwrap(Data(base64Encoded: signature)), signs: Data(message.utf8))
    }

    func testInvalidURLThrowsBeforeAttemptingToUseTheSigningKey() async throws {
        // On Linux Swift 5.10.1 these raw path characters make Foundation return nil.
        // Other Foundation versions may encode them instead; this regression targets Linux Swift 5.10.1.
        let urls = ["a b", "a|b", "a\"b", "a{b"].map {
            "https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/\($0)?mchid=test"
        } + ["https://api.mch.weixin.qq.com/%"]
        var rejected = 0
        for url in urls where URL(string: url) == nil {
            let request = HTTPClientRequest(url: url)
            do {
                _ = try await request.genSign(nonceStr: "offline", timestamp: 1234567890, privateKeyPem: "")
                XCTFail("An unparseable URL must throw before the intentionally absent signing key is used")
            } catch let error as WechatPayRequestSigningError {
                XCTAssertEqual(error, .invalidURL)
                rejected += 1
            }
        }
        #if os(Linux) && compiler(<6.0)
        XCTAssertEqual(rejected, urls.count)
        #else
        if rejected == 0 { throw XCTSkip("This reproduction targets Foundation URL parsing in Swift 5.10") }
        #endif
    }

    func testRecognizableInvalidURLErrorDoesNotIncludeRequestContents() {
        let error = WechatPayRequestSigningError.invalidURL
        XCTAssertEqual(error, .invalidURL)
        XCTAssertEqual(String(describing: error), "invalidURL")
    }

    func testInvalidURLDoesNotReadTheRequestBody() async throws {
        let reads = BodyReads()
        let url = "https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/a b?mchid=test"
        guard URL(string: url) == nil else { throw XCTSkip("This reproduction targets Foundation URL parsing in Swift 5.10") }
        var request = HTTPClientRequest(url: url)
        request.method = .POST
        request.body = .stream(CountingBody(reads: reads), length: .unknown)
        do {
            _ = try await request.genSign(nonceStr: "offline", timestamp: 1234567890, privateKeyPem: "")
            XCTFail("Invalid URL must be rejected before reading or signing the body")
        } catch let error as WechatPayRequestSigningError {
            XCTAssertEqual(error, .invalidURL)
        }
        let count = await reads.count
        XCTAssertEqual(count, 0)
    }

    func testNormalGETSigningBytesRemainUnchanged() async throws {
        var request = HTTPClientRequest(url: "https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/order123?mchid=123456")
        request.method = .GET
        let key = try fixture("test-merchant.key")
        let expected = "GET\n/v3/pay/transactions/out-trade-no/order123?mchid=123456\n1234567890\noffline-request-url\n\n"
        let signature = try await request.genSign(nonceStr: "offline-request-url", timestamp: 1234567890, privateKeyPem: key)
        XCTAssertTrue(try verify(signature, message: expected))
        XCTAssertEqual(signature, RSASigner.sign(text: expected, privateKeyPem: key))
    }

    func testNormalPOSTSigningBytesRemainUnchanged() async throws {
        var request = HTTPClientRequest(url: "https://api.mch.weixin.qq.com/v3/pay/transactions/h5")
        request.method = .POST
        request.body = .bytes(Array("{\"description\":\"offline test\"}".utf8))
        let key = try fixture("test-merchant.key")
        let expected = "POST\n/v3/pay/transactions/h5\n1234567890\noffline-request-url\n{\"description\":\"offline test\"}\n"
        let signature = try await request.genSign(nonceStr: "offline-request-url", timestamp: 1234567890, privateKeyPem: key)
        XCTAssertTrue(try verify(signature, message: expected))
        XCTAssertEqual(signature, RSASigner.sign(text: expected, privateKeyPem: key))
    }

    func testRequestInterceptorPropagatesInvalidURLWithoutAddingAuthorization() async throws {
        let url = "https://api.mch.weixin.qq.com/v3/pay/transactions/out-trade-no/a b?mchid=test"
        guard URL(string: url) == nil else { throw XCTSkip("This reproduction targets Foundation URL parsing in Swift 5.10") }
        var request = HTTPClientRequest(url: url)
        let interceptor = WechatPayRequestInterceptor(mchid: "offline", serialNo: "offline", certificateContent: "")
        do {
            try await interceptor.adapt(urlRequest: &request)
            XCTFail("Invalid URL must be returned as an error before signing or sending")
        } catch let error as WechatPayRequestSigningError {
            XCTAssertEqual(error, .invalidURL)
            XCTAssertNil(request.headers.first(name: "Authorization"))
        }
    }
}
