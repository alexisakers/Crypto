/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
@testable import Crypto

/**
 * A test case that checks the hashing algorithm.
 */

class DigestTests: XCTestCase {

    /**
     * Tests that valid hashes are computed.
     */

    func testComputeHash() {
        performTestSuite(DigestTestSuite.md4)
        performTestSuite(DigestTestSuite.md5)
        performTestSuite(DigestTestSuite.sha1)
        performTestSuite(DigestTestSuite.sha224)
        performTestSuite(DigestTestSuite.sha256)
        performTestSuite(DigestTestSuite.sha384)
        performTestSuite(DigestTestSuite.sha512)
    }

    // MARK: - Utilities

    func performTestSuite(_ testSuite: () -> [MessageHash]) {

        let hashes = testSuite()

        for messageHash in hashes {

            let messageData: Data

            switch messageHash.message {
            case .hex(let string):
                messageData = Data(hexString: string)

            case .text(let string):
                messageData = Data(string.utf8)
            }

            let computedDataHash = messageHash.digest.hash(message: messageData)

            XCTAssertEqual(computedDataHash.count, messageHash.digest.length)
            XCTAssertEqual(computedDataHash, messageHash.expectedHash)

        }

    }

}
