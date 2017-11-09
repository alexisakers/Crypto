/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation

extension Data: ExpressibleByStringLiteral {

    init(hexString: String) {

        var data = [UInt8]()
        var hexIterator = hexString.makeIterator()

        while let c1 = hexIterator.next(), let c2 = hexIterator.next() {

            let s = String([c1, c2])

            guard let d = UInt8(s, radix: 16) else {
                break
            }

            data.append(d)

        }

        self.init(bytes: data)

    }

    public init(stringLiteral value: String) {
        self.init(hexString: value)
    }

    var hexString: String {

        return reduce("") {
            let hex = String($1, radix: 16).uppercased()
            let fullHex = hex.count > 1 ? hex : "0\(hex)"
            return $0 + fullHex
        }

    }

}
