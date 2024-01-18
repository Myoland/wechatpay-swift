//
//  File.swift
//  
//
//  Created by kevinzhow on 2022/6/5.
//

import Foundation

extension URL {
    var pathWithQuery: String {
        var path = self.path
        if let query = self.query {
            path += "?\(query)"
        }
        return path
    }
}
