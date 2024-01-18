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
    struct Client {
        
        enum ClientError: Error {
            case unexpectedResponse(reason: String)
        }
        
        let httpClient: HTTPClient
        let requestInterceptor: WechatPayRequestInterceptor
        var validator: WechatPaySignatureValidator
        
        func request<T: Codable>(_ url: String, method: HTTPMethod, decoder: JSONDecoder? = nil, data: Codable? = nil, validate: Bool = true) async throws -> T {
            var request = HTTPClientRequest(url: url)
            request.method = method
            
            if let data = data {
                request.body = HTTPClientRequest.Body.bytes(ByteBuffer(data:  try JSONEncoder().encode(data)))
                request.headers.replaceOrAdd(name: "Content-Type", value: "application/json")
            }
            
            try await requestInterceptor.adapt(urlRequest: &request)
            
            let response = try await httpClient.execute(request, timeout: .seconds(30))
            
            if response.status == .ok {
                
                let bodyBuffer = try await response.body.collect(upTo: 1024*1024)
                
                if (validate) {
                    try await validator.validate(response: response, body: String(buffer: bodyBuffer))
                }
                
                return try (decoder ?? JSONDecoder()).decode(T.self, from: bodyBuffer)
            } else {
                let bodyBuffer = try await response.body.collect(upTo: 1024*1024)
                
                throw ClientError.unexpectedResponse(reason: String(buffer: bodyBuffer))
            }
            
        }
    }
}
