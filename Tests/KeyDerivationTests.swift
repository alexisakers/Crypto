/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
@testable import Crypto

/**
 * A test case that checks the key derivation algorithm.
 */

class KeyDerivationTests: XCTestCase {

    // MARK: - Calibration

    /**
     * Tests that calibration produces a valid rounds count.
     */

    func testCalibration() throws {

        let rounds = try KeyDerivation.pbkdf2(.hmacSHA256).calibrate(passwordLength: 6,
                                                                     saltLength: 128,
                                                                     derivedKeyLength: 128,
                                                                     delay: 10)

        XCTAssertGreaterThan(rounds, 0)
        XCTAssertGreaterThanOrEqual(rounds, 10_000)
        XCTAssertLessThan(rounds, UInt32.max)

    }

    /**
     * Tests that calibration throws an error in case of failure.
     */

    func testCalibrationError() {

        do {

            let rounds = try KeyDerivation.pbkdf2(.hmacSHA256).calibrate(passwordLength: 6,
                                                                         saltLength: 200,
                                                                         derivedKeyLength: 128,
                                                                         delay: 10)

            XCTFail("Calibration should fail, as parameters are invalid. Computed \(rounds) rounds.")

        } catch {

            guard let cryptoError = error as? CryptoError else {
                XCTFail("Expected a CryptoError.")
                return
            }

            XCTAssertEqual(cryptoError, .unspecifiedError)

        }

    }

    // MARK: - Derivation

    /**
     * Tests that passwords are derived correctly.
     */

    func testDerivation() throws {
        try performTestSuite(PBKDF2TestSuite.hmacSHA1)
        try performTestSuite(PBKDF2TestSuite.hmacSHA256)
        try performTestSuite(PBKDF2TestSuite.hmacSHA512)
    }

    /**
     * Tests that errors are thrown on error.
     */

    func testDerivationError() throws {

        let salt = "salt".data(using: .utf8)!

        do {

            let derivedKey = try KeyDerivation.pbkdf2(.hmacSHA1).derive(password: "password",
                                                                        salt: salt,
                                                                        rounds: 0,
                                                                        derivedKeyLength: 0)

            XCTFail("Derivation should fail, as parameters are invalid. Derived \(derivedKey.count) bytes.")

        } catch {

            guard let cryptoError = error as? CryptoError else {
                XCTFail("Expected a CryptoError.")
                return
            }

            XCTAssertEqual(cryptoError, .illegalParameter)

        }

    }

    // MARK: - Utility

    /**
     * Performs the specified test suite.
     *
     * - parameter testSuite: The test suite to run, represented by the array of test vectors to check.
     */

    func performTestSuite(_ testSuite: () -> [PBKDF2TestVector]) throws {

        let suite = testSuite()

        for vector in suite {

            let salt = vector.salt.data(using: .utf8)!

            let derivedKey = try KeyDerivation.pbkdf2(vector.pseudoRandom).derive(password: vector.password,
                                                                                  salt: salt,
                                                                                  rounds: vector.iter,
                                                                                  derivedKeyLength: vector.dkLen)

            XCTAssertEqual(derivedKey.count, vector.dkLen)
            XCTAssertEqual(derivedKey, vector.expectedKey)

        }

    }

}
