/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import XCTest
@testable import Crypto

/**
 * Represents a PBKDF2 test vector, i.g. the data used to verify our implementation.
 */

struct PBKDF2TestVector {

    let pseudoRandom: KeyDerivation.PseudoRandomAlgorithm
    let password: String
    let salt: String
    let iter: UInt32
    let dkLen: Int

    let expectedKey: Data

    init(_ pseudoRandom: KeyDerivation.PseudoRandomAlgorithm, _ password: String, _ salt: String,
         _ iter: UInt32, _ dkLen: Int, _ expectedKey: Data) {
        self.pseudoRandom = pseudoRandom
        self.password = password
        self.salt = salt
        self.iter = iter
        self.dkLen = dkLen
        self.expectedKey = expectedKey
    }

}

enum PBKDF2TestSuite {}

extension PBKDF2TestSuite {

    static func hmacSHA1() -> [PBKDF2TestVector] {

        let v1 = PBKDF2TestVector(.hmacSHA1, "password", "salt", 1, 20, "0C60C80F961F0E71F3A9B524AF6012062FE037A6")
        let v2 = PBKDF2TestVector(.hmacSHA1, "password", "salt", 2, 20, "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957")
        let v3 = PBKDF2TestVector(.hmacSHA1, "password", "salt", 4096, 20, "4B007901B765489ABEAD49D926F721D065A429C1")
        let v4 = PBKDF2TestVector(.hmacSHA1, "password", "salt", 16777216, 20, "EEFE3D61CD4DA4E4E9945B3D6BA2158C2634E984")
        let v5 = PBKDF2TestVector(.hmacSHA1, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038")
        let v6 = PBKDF2TestVector(.hmacSHA1, "pass\0word", "sa\0lt", 4096, 16, "56FA6AA75548099DCC37D7F03425E0C3")

        return [v1, v2, v3, v4, v5, v6]

    }

    static func hmacSHA256() -> [PBKDF2TestVector] {

        let v1 = PBKDF2TestVector(.hmacSHA256, "password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        let v2 = PBKDF2TestVector(.hmacSHA256, "password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        let v3 = PBKDF2TestVector(.hmacSHA256, "password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        let v5 = PBKDF2TestVector(.hmacSHA256, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")
        let v6 = PBKDF2TestVector(.hmacSHA256, "pass\0word", "sa\0lt", 4096, 16, "89b69d0516f829893c696226650a8687")

        return [v1, v2, v3, v5, v6]

    }

    static func hmacSHA512() -> [PBKDF2TestVector] {

        let v1 = PBKDF2TestVector(.hmacSHA512, "password", "salt", 1, 64, "867F70CF1ADE02CFF3752599A3A53DC4AF34C7A669815AE5D513554E1C8CF252C02D470A285A0501BAD999BFE943C08F050235D7D68B1DA55E63F73B60A57FCE")
        let v2 = PBKDF2TestVector(.hmacSHA512, "password", "salt", 2, 64, "E1D9C16AA681708A45F5C7C4E215CEB66E011A2E9F0040713F18AEFDB866D53CF76CAB2868A39B9F7840EDCE4FEF5A82BE67335C77A6068E04112754F27CCF4E")
        let v3 = PBKDF2TestVector(.hmacSHA512, "password", "salt", 4096, 64, "D197B1B33DB0143E018B12F3D1D1479E6CDEBDCC97C5C0F87F6902E072F457B5143F30602641B3D55CD335988CB36B84376060ECD532E039B742A239434AF2D5")
        let v5 = PBKDF2TestVector(.hmacSHA512, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 64, "8C0511F4C6E597C6AC6315D8F0362E225F3C501495BA23B868C005174DC4EE71115B59F9E60CD9532FA33E0F75AEFE30225C583A186CD82BD4DAEA9724A3D3B8")

        return [v1, v2, v3, v5]

    }

}
