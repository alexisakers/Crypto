/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import XCTest
@testable import Crypto

/**
 * Represents a HMAC test vector, i.g. the data used to verify our implementation.
 */

struct HMACTestVector {

    /// The HMAC instance to use.
    let hmac: HMAC

    /// The key used to generate the hash.
    let key: Data

    /// The hashed message.
    let message: Data

    /// The expected hash.
    let expectedHash: Data

    /// The verification function (to test the result).
    let verificationFunction: (Data, Data) -> Void

    init(_ hmac: HMAC, _ key: Data, _ message: Data, _ expectedHash: Data, isValid: Bool = true) {
        self.hmac = hmac
        self.key = key
        self.message = message
        self.expectedHash = expectedHash
        self.verificationFunction = isValid ? { XCTAssertEqual($0, $1) } : { XCTAssertNotEqual($0, $1) }
    }

}

enum HMACTestSuite {}

// MARK: - Valid Test Vectors

extension HMACTestSuite {

    static func rfc4231_1() -> [HMACTestVector] {

        let key: Data = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        let message: Data = "4869205468657265"

        let sha224Hash: Data = "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"
        let sha256Hash: Data = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        let sha384Hash: Data = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
        let sha512Hash: Data = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"

        let sha224 = HMACTestVector(.sha224, key, message, sha224Hash)
        let sha256 = HMACTestVector(.sha256, key, message, sha256Hash)
        let sha384 = HMACTestVector(.sha384, key, message, sha384Hash)
        let sha512 = HMACTestVector(.sha512, key, message, sha512Hash)

        return [sha224, sha256, sha384, sha512]

    }

    static func rfc4231_2() -> [HMACTestVector] {

        let key: Data = "4a656665"
        let message: Data = "7768617420646f2079612077616e7420666f72206e6f7468696e673f"

        let sha224Hash: Data = "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"
        let sha256Hash: Data = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        let sha384Hash: Data = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        let sha512Hash: Data = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"

        let sha224 = HMACTestVector(.sha224, key, message, sha224Hash)
        let sha256 = HMACTestVector(.sha256, key, message, sha256Hash)
        let sha384 = HMACTestVector(.sha384, key, message, sha384Hash)
        let sha512 = HMACTestVector(.sha512, key, message, sha512Hash)

        return [sha224, sha256, sha384, sha512]

    }

    static func rfc4231_3() -> [HMACTestVector] {

        let key: Data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let message: Data = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

        let sha224Hash: Data = "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea"
        let sha256Hash: Data = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        let sha384Hash: Data = "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27"
        let sha512Hash: Data = "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"

        let sha224 = HMACTestVector(.sha224, key, message, sha224Hash)
        let sha256 = HMACTestVector(.sha256, key, message, sha256Hash)
        let sha384 = HMACTestVector(.sha384, key, message, sha384Hash)
        let sha512 = HMACTestVector(.sha512, key, message, sha512Hash)

        return [sha224, sha256, sha384, sha512]

    }

    static func rfc4231_4() -> [HMACTestVector] {

        let key: Data = "0102030405060708090a0b0c0d0e0f10111213141516171819"
        let message: Data = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

        let sha224Hash: Data = "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a"
        let sha256Hash: Data = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        let sha384Hash: Data = "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"
        let sha512Hash: Data = "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"

        let sha224 = HMACTestVector(.sha224, key, message, sha224Hash)
        let sha256 = HMACTestVector(.sha256, key, message, sha256Hash)
        let sha384 = HMACTestVector(.sha384, key, message, sha384Hash)
        let sha512 = HMACTestVector(.sha512, key, message, sha512Hash)

        return [sha224, sha256, sha384, sha512]

    }

    static func rfc4231_6() -> [HMACTestVector] {

        let key: Data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let message: Data = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"

        let sha224Hash: Data = "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e"
        let sha256Hash: Data = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        let sha384Hash: Data = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
        let sha512Hash: Data = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"

        let sha224 = HMACTestVector(.sha224, key, message, sha224Hash)
        let sha256 = HMACTestVector(.sha256, key, message, sha256Hash)
        let sha384 = HMACTestVector(.sha384, key, message, sha384Hash)
        let sha512 = HMACTestVector(.sha512, key, message, sha512Hash)

        return [sha224, sha256, sha384, sha512]

    }

    static func rfc4231_7() -> [HMACTestVector] {

        let key: Data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let message: Data = "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"

        let sha224Hash: Data = "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1"
        let sha256Hash: Data = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        let sha384Hash: Data = "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"
        let sha512Hash: Data = "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"

        let sha224 = HMACTestVector(.sha224, key, message, sha224Hash)
        let sha256 = HMACTestVector(.sha256, key, message, sha256Hash)
        let sha384 = HMACTestVector(.sha384, key, message, sha384Hash)
        let sha512 = HMACTestVector(.sha512, key, message, sha512Hash)

        return [sha224, sha256, sha384, sha512]

    }

    static func rfc2202() -> [HMACTestVector] {

        let case1_key: Data = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        let case1_message: Data = "4869205468657265"
        let case1_sha1Hash: Data = "b617318655057264e28bc0b6fb378c8ef146be00"
        let case1_vector = HMACTestVector(.sha1, case1_key, case1_message, case1_sha1Hash)

        let case2_key: Data = "4a656665"
        let case2_message: Data = "7768617420646f2079612077616e7420666f72206e6f7468696e673f"
        let case2_sha1Hash: Data = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        let case2_vector = HMACTestVector(.sha1, case2_key, case2_message, case2_sha1Hash)

        let case3_key: Data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let case3_message: Data = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        let case3_sha1Hash: Data = "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        let case3_vector = HMACTestVector(.sha1, case3_key, case3_message, case3_sha1Hash)

        let case4_key: Data = "0102030405060708090a0b0c0d0e0f10111213141516171819"
        let case4_message: Data = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        let case4_sha1Hash: Data = "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
        let case4_vector = HMACTestVector(.sha1, case4_key, case4_message, case4_sha1Hash)

        let case5_key: Data = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
        let case5_message: Data = "546573742057697468205472756e636174696f6e"
        let case5_sha1Hash: Data = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
        let case5_vector = HMACTestVector(.sha1, case5_key, case5_message, case5_sha1Hash)

        let case6_key: Data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let case6_message: Data = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"
        let case6_sha1Hash: Data = "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        let case6_vector = HMACTestVector(.sha1, case6_key, case6_message, case6_sha1Hash)

        let case7_key: Data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let case7_message: Data = "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461"
        let case7_sha1Hash: Data = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        let case7_vector = HMACTestVector(.sha1, case7_key, case7_message, case7_sha1Hash)

        return [
            case1_vector, case2_vector, case3_vector, case4_vector, case5_vector, case6_vector, case7_vector
        ]

    }

}

// MARK: - Invalid Test Vectors

extension HMACTestSuite {

    static func wrongHashes() -> [HMACTestVector] {

        let key: Data = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        let message: Data = "4869205468657265"

        let sha1Hash: Data = "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
        let sha224Hash: Data = "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e"
        let sha256Hash: Data = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        let sha384Hash: Data = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
        let sha512Hash: Data = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"

        let sha1 = HMACTestVector(.sha1, key, message, sha1Hash, isValid: false)
        let sha224 = HMACTestVector(.sha224, key, message, sha224Hash, isValid: false)
        let sha256 = HMACTestVector(.sha256, key, message, sha256Hash, isValid: false)
        let sha384 = HMACTestVector(.sha384, key, message, sha384Hash, isValid: false)
        let sha512 = HMACTestVector(.sha512, key, message, sha512Hash, isValid: false)

        return [sha1, sha224, sha256, sha384, sha512]

    }

}
