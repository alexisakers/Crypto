/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import CommonCrypto
import Security

/**
 * Random bytes generators.
 */

public enum Random {

    /// The CommonCrypto random bytes generator.
    case commonCrypto

    /// The Security.framework random bytes generator.
    case security

    /**
     * Generates the specified number of random bytes and throws an error in case of failure.
     *
     * - parameter bytes: The number of bytes to generate.
     * - throws: If generation fails, throws a `CryptoError` object.
     * - returns: A Data buffer filled with the random bytes.
     */

    public func generate(bytes: Int) throws -> Data {

        let bytesAlignment = MemoryLayout<UInt8>.alignment
        let outputBytes = UnsafeMutableRawPointer.allocate(bytes: bytes, alignedTo: bytesAlignment)

        defer {
            outputBytes.deallocate(bytes: bytes, alignedTo: bytesAlignment)
        }

        switch self {
        case .commonCrypto:

            let status = CCRandomGenerateBytes(outputBytes, bytes)

            if let error = CryptoError(status: status) {
                throw error
            }

        case .security:

            let status = SecRandomCopyBytes(kSecRandomDefault, bytes, outputBytes)

            guard status == errSecSuccess else {
                throw CryptoError.unknownStatus(status)
            }

        }

        let randomBytes = UnsafeRawPointer(outputBytes)
        return Data(bytes: randomBytes, count: bytes)

    }

}
