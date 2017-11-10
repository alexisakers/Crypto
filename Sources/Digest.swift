/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import CommonCrypto

/**
 * An enumeration of digest algorithms.
 *
 * Use objects of this type to generate the MD and SHA hash digest of messages.
 */

public enum Digest {

    /// The MD4 hashing algorithm.
    case md4

    /// The MD5 hashing algorithm.
    case md5

    /// The SHA-1 hashing algorithm.
    case sha1

    /// The SHA-224 hashing algorithm.
    case sha224

    /// The SHA-256 hashing algorithm.
    case sha256

    /// The SHA-384 hashing algorithm.
    case sha384

    /// The SHA-512 hashing algorithm.
    case sha512

}

// MARK: - Algorithm Properties

private typealias DigestFunction = (UnsafeRawPointer?, CC_LONG, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>!

extension Digest {

    /// The function to use to produce the digests.
    fileprivate var hashFunction: DigestFunction {

        switch self {
        case .md4: return CC_MD4
        case .md5: return CC_MD5
        case .sha1: return CC_SHA1
        case .sha224: return CC_SHA224
        case .sha256: return CC_SHA256
        case .sha384: return CC_SHA384
        case .sha512: return CC_SHA512
        }

    }

    /// The length of digests produced by the algorithm.
    public var length: Int {

        switch self {
        case .md4: return Int(CC_MD4_DIGEST_LENGTH)
        case .md5: return Int(CC_MD5_DIGEST_LENGTH)
        case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
        case .sha224: return Int(CC_SHA224_DIGEST_LENGTH)
        case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
        case .sha384: return Int(CC_SHA384_DIGEST_LENGTH)
        case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
        }

    }

}

// MARK: - Computation

extension Digest {

    /**
     * Calculates the hash of the message and returns it as a Data buffer.
     *
     * - parameter message: The message to hash.
     * - returns: The bytes of the calculated hash.
     */

    public func hash(message: Data) -> Data {

        var buffer = Data(count: length)

        buffer.write(withPointerTo: message) { bufferPtr, messageBytes in
            let messagePtr = UnsafeRawPointer(messageBytes)
            let resultPtr = self.hashFunction(messagePtr , CC_LONG(message.count), bufferPtr)!
            bufferPtr.assign(from: resultPtr, count: self.length)
        }

        return buffer

    }

}
