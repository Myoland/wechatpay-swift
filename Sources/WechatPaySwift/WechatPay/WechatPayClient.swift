//
//  File.swift
//
//
//  Created by kevinzhow on 2024/1/6.
//

import Foundation
import AsyncHTTPClient
import NIOHTTP1
import NIOCore
import NIOFoundationCompat

extension WechatPay {
    public struct Client {
        
        public enum ClientError: Error {
            case unexpectedResponse(reason: String)
        }

        /// Owned by the default transport only; nil when a custom transport is injected.
        let httpClient: HTTPClient?
        let requestInterceptor: WechatPayRequestInterceptor
        var validator: WechatPaySignatureValidator
        let transport: any WechatPayTransport

        init(httpClient: HTTPClient, requestInterceptor: WechatPayRequestInterceptor, validator: WechatPaySignatureValidator) {
            self.httpClient = httpClient
            self.requestInterceptor = requestInterceptor
            self.validator = validator
            self.transport = AsyncHTTPClientWechatPayTransport(httpClient: httpClient)
        }

        init(transport: any WechatPayTransport, requestInterceptor: WechatPayRequestInterceptor, validator: WechatPaySignatureValidator) {
            self.httpClient = nil
            self.requestInterceptor = requestInterceptor
            self.validator = validator
            self.transport = transport
        }

        /// Signs and sends one request. The response is NOT verified here.
        func exchange(_ url: String, method: HTTPMethod, body: Data?) async throws -> WechatPayTransportResponse {
            try await validator.validateResponsePublicKey(requestInterceptor.responsePublicKey)
            var request = HTTPClientRequest(url: url)
            request.method = method
            if let body {
                request.body = HTTPClientRequest.Body.bytes(ByteBuffer(data: body))
                request.headers.replaceOrAdd(name: "Content-Type", value: "application/json")
            }

            try await requestInterceptor.adapt(urlRequest: &request)

            let response = try await transport.execute(
                WechatPayTransportRequest(method: method, url: url, headers: request.headers, body: body),
                timeout: .seconds(30))
            guard response.body.count <= wechatPayMaximumResponseBytes else {
                throw ClientError.unexpectedResponse(reason: "response body too large")
            }
            return response
        }

        func request<T: Codable>(_ url: String, method: HTTPMethod, decoder: JSONDecoder? = nil, data: Codable? = nil) async throws -> T {
            let body = try data.map { try JSONEncoder().encode($0) }

            let response = try await exchange(url, method: method, body: body)

            if response.status == 200 {
                try await validator.validate(headers: response.headers, body: String(decoding: response.body, as: UTF8.self))

                return try (decoder ?? JSONDecoder()).decode(T.self, from: response.body)
            } else {
                throw ClientError.unexpectedResponse(reason: String(decoding: response.body, as: UTF8.self))
            }
        }
    }
}
