/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
@testable import Crypto

/**
 * A test case that checks the key wrap algorithm.
 */

class KeyWrapTests: XCTestCase {

    func testWrap() throws {
        try performWrap(AESKeyWrapTestSuite.rfc3394)
    }

    func testUnwrap() throws {
        try performUnwrap(AESKeyWrapTestSuite.rfc3394)
    }

    // MARK: - Utilities

    func performWrap(_ testSuite: () -> [AESKeyWrapTestVector]) throws {

        let vectors = testSuite()

        for vector in vectors {
            let wrapped = try SymmetricKeyWrap.aes.wrap(key: vector.key, encryptionKey: vector.kek)
            XCTAssertEqual(wrapped, vector.wrappedKey)
        }

    }

    func performUnwrap(_ testSuite: () -> [AESKeyWrapTestVector]) throws {

        let vectors = testSuite()

        for vector in vectors {
            let unwrapped = try SymmetricKeyWrap.aes.unwrap(key: vector.wrappedKey, encryptionKey: vector.kek)
            XCTAssertEqual(unwrapped, vector.key)
        }

    }

}
