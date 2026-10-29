import Foundation
import AsyncHTTPClient
import NIOCore
import NIOHTTP1
import NIOFoundationCompat

/// A request that has already been signed by the SDK's merchant request interceptor.
public struct WechatPayTransportRequest: Sendable {
    public let method: HTTPMethod
    public let url: String
    public let headers: HTTPHeaders
    public let body: Data?
}

/// The provider's raw response. The SDK verifies the platform signature itself;
/// a transport can neither skip nor replace that verification.
public struct WechatPayTransportResponse: Sendable {
    public let status: Int
    public let headers: HTTPHeaders
    public let body: Data

    public init(status: Int, headers: HTTPHeaders, body: Data) {
        self.status = status
        self.headers = headers
        self.body = body
    }
}

/// Executes one signed HTTP exchange. The default implementation is AsyncHTTPClient.
/// Custom transports exist for offline tests and must not rewrite the URL or body.
public protocol WechatPayTransport: Sendable {
    func execute(_ request: WechatPayTransportRequest, timeout: TimeAmount) async throws -> WechatPayTransportResponse
}

/// Response bodies above this size are rejected before parsing or signature verification.
let wechatPayMaximumResponseBytes = 1024 * 1024

struct AsyncHTTPClientWechatPayTransport: WechatPayTransport {
    let httpClient: HTTPClient

    func execute(_ request: WechatPayTransportRequest, timeout: TimeAmount) async throws -> WechatPayTransportResponse {
        var outbound = HTTPClientRequest(url: request.url)
        outbound.method = request.method
        outbound.headers = request.headers
        if let body = request.body {
            outbound.body = .bytes(ByteBuffer(data: body))
        }
        let response = try await httpClient.execute(outbound, timeout: timeout)
        let buffer = try await response.body.collect(upTo: wechatPayMaximumResponseBytes)
        return WechatPayTransportResponse(status: Int(response.status.code), headers: response.headers,
                                          body: Data(buffer: buffer))
    }
}
