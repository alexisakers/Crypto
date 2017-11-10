/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
@testable import Crypto

/**
 * A test case that checks the HMAC algorithm.
 */

class HMACTests: XCTestCase {

    /**
     * Tests computing hashes.
     */

    func testHashComputation() {

        // RFC-4231 Test Vectors

        performTestSuite(HMACTestSuite.rfc4231_1)
        performTestSuite(HMACTestSuite.rfc4231_2)
        performTestSuite(HMACTestSuite.rfc4231_3)
        performTestSuite(HMACTestSuite.rfc4231_4)
        performTestSuite(HMACTestSuite.rfc4231_6)
        performTestSuite(HMACTestSuite.rfc4231_7)

        // RFC-2202 Test Vectors (SHA-1)

        performTestSuite(HMACTestSuite.rfc2202)

    }

    /**
     * Tests that wrong hashes are detected.
     */

    func testWrongHashDetection() {
        performTestSuite(HMACTestSuite.wrongHashes)
    }

    // MARK: - Utility

    /**
     * Performs the specified test suite.
     *
     * - parameter testSuite: The test suite to run, represented by the array of test vectors to check.
     */

    func performTestSuite(_ testSuite: () -> [HMACTestVector]) {

        let suite = testSuite()

        for vector in suite {
            let hash = vector.hmac.authenticate(vector.message, with: vector.key)
            vector.verificationFunction(hash, vector.expectedHash)
        }

    }

}
