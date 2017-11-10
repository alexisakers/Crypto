/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
@testable import Crypto

/**
 * A test case that checks the symmetric encryption/decryption algorithm.
 */

class CryptorTests: XCTestCase {

    /**
     * Tests encrypting and decrypting random data.
     */

    func testRoundCryptRandomData() throws {

        let aes = Cryptor.aes256

        let data = try SecRandom.generate(bytes: 256)
        let key = try SecRandom.generate(bytes: aes.keySize)
        let iv = try SecRandom.generate(bytes: aes.blockSize)

        let encryptedData = try aes.encrypt(data: data, withKey: key, iv: iv)
        let decryptedData = try aes.decrypt(data: encryptedData, withKey: key, iv: iv)

        XCTAssertEqual(data, decryptedData)

    }

    /**
     * Tests the cryptor with test vectors.
     */

    func testCryptor() throws {
        try performTestSuite(SymmetricTestSuite.aes128)
    }

    // MARK: - Utilities

    func performTestSuite(_ testSuite: () -> [SymmetricTestVector]) throws {

        let testVectors = testSuite()

        for testVector in testVectors {

            let encryptedData = try testVector.cryptor.encrypt(data: testVector.message,
                                                               withKey: testVector.key,
                                                               iv: testVector.iv)

            XCTAssertEqual(encryptedData, testVector.encryptedMessage)

            let decryptedData = try testVector.cryptor.decrypt(data: testVector.encryptedMessage,
                                                               withKey: testVector.key,
                                                               iv: testVector.iv)

            XCTAssertEqual(decryptedData, testVector.message)
            print(decryptedData.hexString, testVector.message.hexString)

        }

    }

}
