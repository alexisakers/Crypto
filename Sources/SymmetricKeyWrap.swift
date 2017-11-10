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
    fileprivate var algorithm: CCWrappingAlgorithm {

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
        var buffer = Data(count: outputSize)

        var wrappedKeyLength = outputSize

        let result = buffer.write(withPointerTo: encryptionKey, key) { bufferPtr, encryptionKeyPtr, keyPtr in

            CCSymmetricKeyWrap(self.algorithm,
                               CCrfc3394_iv,
                               CCrfc3394_ivLen,
                               encryptionKeyPtr,
                               encryptionKey.count,
                               keyPtr,
                               key.count,
                               bufferPtr,
                               &wrappedKeyLength)

        }

        if let error = CryptoError(status: result) {
            throw error
        }

        return buffer.prefix(upTo: wrappedKeyLength)

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
        var buffer = Data(count: outputSize)

        var unwrappedKeyLength = outputSize

        let result = buffer.write(withPointerTo: encryptionKey, key) { bufferPtr, encryptionKeyPtr, keyPtr in

            CCSymmetricKeyUnwrap(self.algorithm,
                                 CCrfc3394_iv,
                                 CCrfc3394_ivLen,
                                 encryptionKeyPtr,
                                 encryptionKey.count,
                                 keyPtr,
                                 key.count,
                                 bufferPtr,
                                 &unwrappedKeyLength)

        }

        if let error = CryptoError(status: result) {
            throw error
        }

        return buffer.prefix(upTo: unwrappedKeyLength)

    }

}
