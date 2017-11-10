/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
import Foundation
@testable import Crypto

struct SymmetricTestVector {

    let cryptor: Cryptor
    let key: Data
    let iv: Data
    let message: Data
    let encryptedMessage: Data

    init(_ cryptor: Cryptor, _ key: Data, _ iv: Data, _ message: Data, _ encryptedMessage: Data) {
        self.cryptor = cryptor
        self.key = key
        self.iv = iv
        self.message = message
        self.encryptedMessage = encryptedMessage
    }

}

enum SymmetricTestSuite {}

extension SymmetricTestSuite {

    static func aes128() -> [SymmetricTestVector] {

        let key: Data = "000102030405060708090a0b0c0d0e0f"
        let iv: Data = "0f0e0d0c0b0a09080706050403020100"

        let v1 = SymmetricTestVector(.aes128, key, iv,
                                     "0a",
                                     "a385b047a4108a8748bf96b435738213")

        let v2 = SymmetricTestVector(.aes128, key, iv,
                                     "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                                     "324a44cf3395b14214861084019f9257")

        let v3 = SymmetricTestVector(.aes128, key, iv,
                                     "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                                     "16d67a52c1e8384f7ed887c2011605346544febcf84574c334f1145d17567047")

        let v4 = SymmetricTestVector(.aes128, key, iv,
                                     "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
                                     "16d67a52c1e8384f7ed887c2011605348b72cecb00bbc00f328af6bb69085b02")

        return [v1, v2, v3, v4]

    }

}
