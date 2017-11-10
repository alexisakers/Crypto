/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
@testable import Crypto

/**
 * A test case that checks the random bytes generation algorithm.
 */

class RandomTests: XCTestCase {

    /**
     * Tests generating random bytes using CommonRandom.
     */

    func testCommonCrypto() throws {
        let randomBytes = try CommonRandom.generate(bytes: 128)
        XCTAssertEqual(randomBytes.count, 128)
    }

    /**
     * Tests generating random bytes using SecRandom.
     */

    func testSecurity() throws {
        let randomBytes = try SecRandom.generate(bytes: 128)
        XCTAssertEqual(randomBytes.count, 128)
    }

}
