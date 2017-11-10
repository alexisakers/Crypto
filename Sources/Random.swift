/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import CommonCrypto
import Security

/**
 * A generic random bytes generators.
 */

public protocol Random {

    /**
     * Generates the specified number of random bytes and throws an error in case of failure.
     *
     * - parameter bytes: The number of bytes to generate.
     * - throws: If generation fails, throws a `CryptoError` object.
     * - returns: A Data buffer filled with the random bytes.
     */

    static func generate(bytes: Int) throws -> Data

}

/**
 * The CommonCrypto random bytes generator.
 */

public enum CommonRandom: Random {

    public static func generate(bytes: Int) throws -> Data {

        var buffer = Data(count: bytes)

        try buffer.withUnsafeMutableBytes { (ptr: UnsafeMutablePointer<UInt8>) in

            let status = CCRandomGenerateBytes(UnsafeMutableRawPointer(ptr), bytes)

            if let error = CryptoError(status: status) {
                throw error
            }

        }

        return buffer

    }

}

/**
 * The Security.framework random bytes generator.
 */

public enum SecRandom: Random {

    public static func generate(bytes: Int) throws -> Data {

        var buffer = Data(count: bytes)

        try buffer.withUnsafeMutableBytes { (ptr: UnsafeMutablePointer<UInt8>) in

            let status = SecRandomCopyBytes(kSecRandomDefault, bytes, UnsafeMutableRawPointer(ptr))

            guard status == errSecSuccess else {
                throw CryptoError.unknownStatus(status)
            }

        }

        return buffer

    }

}
