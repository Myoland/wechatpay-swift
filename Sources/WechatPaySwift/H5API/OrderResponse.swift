//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/5/28.
//

import Foundation

extension WechatPay.H5API {
    public struct OrderResponse: Codable {
      public let h5URL: URL

      private enum CodingKeys: String, CodingKey {
        case h5URL = "h5_url"
      }
    }
}
