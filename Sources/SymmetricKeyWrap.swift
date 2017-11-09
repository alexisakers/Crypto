/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */


import Foundation
import CommonCrypto

/**
 * Encrypts and encapsulates encryption keys using an encryption key.
 */

public enum SymmetricKeyWrap {

    /// AES key wrapping (RFC-3394).
    case aes

}

// MARK: - Algorithm Properties

extension SymmetricKeyWrap {

    /// The raw algorithm identifier for CommonCrypto.
    private var algorithm: CCWrappingAlgorithm {

        switch self {
        case .aes: return CCWrappingAlgorithm(kCCWRAPAES)
        }

    }

}

// MARK: - Wrap/Unwrap

extension SymmetricKeyWrap {

    /**
     * Wrap a symmetric key with a Key Encryption Key (KEK).
     *
     * This uses the standard RFC-3394 IV provided by CommonCrypto.
     *
     * - parameter key: The key to wrap.
     * - parameter encryptionKey: The Key Encryption Key to be used to wrap the raw key.
     *
     * - throws: In case of failure, this method throws a `CryptoError`.
     * - returns: A Data buffer containing the resulting wrapped key produced by the function.
     */

    public func wrap(key: Data, encryptionKey: Data) throws -> Data {

        let outputSize = CCSymmetricWrappedSize(algorithm, key.count)
        let outputBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: outputSize)

        defer {
            outputBytes.deallocate(capacity: outputSize)
        }

        var wrappedKeyLength = outputSize

        let result = encryptionKey.withUnsafeBytes { (encryptionKeyBytes: UnsafePointer<UInt8>) in

            key.withUnsafeBytes { (keyBytes: UnsafePointer<UInt8>) in

                CCSymmetricKeyWrap(algorithm,
                                   CCrfc3394_iv,
                                   CCrfc3394_ivLen,
                                   encryptionKeyBytes,
                                   encryptionKey.count,
                                   keyBytes,
                                   key.count,
                                   outputBytes,
                                   &wrappedKeyLength)

            }

        }

        if let error = CryptoError(status: result) {
            throw error
        }

        let wrappedKeyBytes = UnsafeRawPointer(outputBytes)
        return Data(bytes: wrappedKeyBytes, count: wrappedKeyLength)

    }

    /**
     * Unwrap a symmetric key with a Key Encryption Key (KEK).
     *
     * This uses the standard RFC-3394 IV provided by CommonCrypto.
     *
     * - parameter key: The wrapped key to unwrap.
     * - parameter encryptionKey: The Key Encryption Key to be used to unwrap the raw key.
     *
     * - throws: In case of failure, this method throws a `CryptoError`.
     * - returns: A Data buffer containing the unwrapped original key.
     */

    public func unwrap(key: Data, encryptionKey: Data) throws -> Data {

        let outputSize = CCSymmetricUnwrappedSize(algorithm, key.count)
        let outputBytes = UnsafeMutablePointer<UInt8>.allocate(capacity: outputSize)

        defer {
            outputBytes.deallocate(capacity: outputSize)
        }

        var unwrappedKeySize = outputSize

        let result = encryptionKey.withUnsafeBytes { (encryptionKeyBytes: UnsafePointer<UInt8>) in

            key.withUnsafeBytes { (keyBytes: UnsafePointer<UInt8>) in

                CCSymmetricKeyUnwrap(algorithm,
                                     CCrfc3394_iv,
                                     CCrfc3394_ivLen,
                                     encryptionKeyBytes,
                                     encryptionKey.count,
                                     keyBytes,
                                     key.count,
                                     outputBytes,
                                     &unwrappedKeySize)

            }

        }

        if let error = CryptoError(status: result) {
            throw error
        }

        let unwrappedKeyBytes = UnsafeRawPointer(outputBytes)
        return Data(bytes: unwrappedKeyBytes, count: unwrappedKeySize)

    }

}
