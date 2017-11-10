/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import CommonCrypto

/**
 * An enumeration of HMAC algorithms.
 *
 * Use objects of this type to authenticate messages with HMAC hashes.
 */

public enum HMAC: Int {

    /// The HMAC-SHA-1 algorithm.
    case sha1 = 1

    /// The HMAC-SHA-224 algorithm.
    case sha224 = 224

    /// The HMAC-SHA-256 algorithm.
    case sha256 = 256

    /// The HMAC-SHA-384 algorithm.
    case sha384 = 384

    /// The HMAC-SHA-512 algorithm.
    case sha512 = 512

}

// MARK: - Algorithm Details

extension HMAC {

    /// The raw algorithm identifier for CommonCrypto.
    fileprivate var algorithm: CCHmacAlgorithm {

        switch self {
        case .sha1: return CCHmacAlgorithm(kCCHmacAlgSHA1)
        case .sha224: return CCHmacAlgorithm(kCCHmacAlgSHA224)
        case .sha256: return CCHmacAlgorithm(kCCHmacAlgSHA256)
        case .sha384: return CCHmacAlgorithm(kCCHmacAlgSHA384)
        case .sha512: return CCHmacAlgorithm(kCCHmacAlgSHA512)
        }

    }

    /// The length of digests produced by the algorithm.
    public var digestLength: Int {

        switch self {
        case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
        case .sha224: return Int(CC_SHA224_DIGEST_LENGTH)
        case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
        case .sha384: return Int(CC_SHA384_DIGEST_LENGTH)
        case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
        }

    }

}

// MARK: - Hash Computation

extension HMAC {

    /**
     * Authenticates the message with the specified key. This generates the HMAC digest for the message.
     *
     * - parameter message: The message to authenticate.
     * - parameter key: The key to use to sign the message.
     *
     * - returns: The HMAC digest as a `Data` object.
     */

    public func authenticate(_ message: Data, with key: Data) -> Data {

        var buffer = Data(count: digestLength)

        buffer.write(withPointerTo: message, key) { bufferPtr, messageBytes, keyBytes in

            CCHmac(self.algorithm,
                    UnsafeRawPointer(keyBytes),
                    key.count,
                    UnsafeRawPointer(messageBytes),
                    message.count,
                    UnsafeMutableRawPointer(bufferPtr))

        }

        return buffer

    }

}
