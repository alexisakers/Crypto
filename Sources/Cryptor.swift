/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import CommonCrypto

/**
 * Provides block cipher based symmetric encryption and decryption of data.
 */

public enum Cryptor {

    /// Advanced Encryption Standard, 128-bit block, 128-bit key.
    case aes128

    /// Advanced Encryption Standard, 128-bit block, 192-bit key.
    case aes192

    /// Advanced Encryption Standard, 128-bit block, 256-bit key.
    case aes256

    /// Data Encryption Standard.
    case des

    /// Triple-DES (3DES), three key, EDE configuration.
    case tripleDES

}

// MARK: - Algorithm Properties

extension Cryptor {

    /// The raw algorith identifier for use with CommonCrypto.
    fileprivate var algorithm: CCAlgorithm {

        switch self {
        case .aes128, .aes192, .aes256: return CCAlgorithm(kCCAlgorithmAES)
        case .des: return CCAlgorithm(kCCAlgorithmDES)
        case .tripleDES: return CCAlgorithm(kCCAlgorithm3DES)
        }

    }

    /**
     * The required size of keys for this algorithm.
     *
     * Use this property to generate random keys or to derive passwords with PBKDF2.
     */

    public var keySize: Int {

        switch self {
        case .aes128: return kCCKeySizeAES128
        case .aes192: return kCCKeySizeAES192
        case .aes256: return kCCKeySizeAES256
        case .des: return kCCKeySizeDES
        case .tripleDES: return kCCKeySize3DES
        }

    }

    /**
     * The size of blocks, in bytes, for the algorithm.
     *
     * Use this property to generate random Initialization Vectors (IV).
     */

    public var blockSize: Int {

        switch self {
        case .aes128, .aes192, .aes256: return kCCBlockSizeAES128
        case .des: return kCCBlockSizeDES
        case .tripleDES: return kCCBlockSize3DES
        }

    }

}

// MARK: - Crypto

extension Cryptor {

    /**
     * Encrypts the data.
     *
     * This method uses Cipher Block Chaining (CBC) mode and PKCS7 padding.
     *
     * - parameter data: The data to encrypt.
     * - parameter key: The raw encryption key bytes.
     * - parameter iv: The initialization vector. Must be the same size as the
     * algorithm's block size (see `blockSize`). Always use random data as the `iv`.
     *
     * - throws: In case of failure, this method throws a `CryptoError` object.
     * - returns: A Data buffer containing the encrypted bytes.
     */

    public func encrypt(data: Data, withKey key: Data, iv: Data) throws -> Data {
        let outputSize = data.count + blockSize
        return try crypt(kCCEncrypt, data, key, iv, outputSize)
    }

    /**
     * Decrypts the encrypted data.
     *
     * The data must be encrypted using Cipher Block Chaining (CBC) mode and PKCS7 padding.
     *
     * - parameter data: The data to decrypt.
     * - parameter key: The raw encryption key bytes.
     * - parameter iv: The initialization vector used to encrypt the data. Must be the same size
     * as the algorithm's block size (see `blockSize`).
     *
     * - throws: In case of failure, this method throws a `CryptoError` object.
     * - returns: A Data buffer containing the decrypted bytes.
     */

    public func decrypt(data: Data, withKey key: Data, iv: Data) throws -> Data {
        let outputSize = data.count + blockSize
        return try crypt(kCCDecrypt, data, key, iv, outputSize)
    }

    private func crypt(_ op: Int, _ message: Data, _ key: Data, _ iv: Data, _ outputSize: Int) throws -> Data {

        guard iv.count == blockSize else {
            throw CryptoError.illegalParameter
        }

        var buffer = Data(count: outputSize)
        var dataOutMoved: Int = 0

        let result = buffer.write(withPointerTo: key, iv, message) { bufferPtr, keyPtr, iVPtr, messagePtr in

            CCCrypt(CCOperation(op),
                    self.algorithm,
                    CCOptions(kCCOptionPKCS7Padding),
                    UnsafeRawPointer(keyPtr), self.keySize,
                    UnsafeRawPointer(iVPtr),
                    UnsafeRawPointer(messagePtr), message.count,
                    bufferPtr, outputSize,
                    &dataOutMoved)

        }

        if let error = CryptoError(status: result) {

            if error == .bufferTooSmall {
                return try crypt(op, message, key, iv, dataOutMoved)
            }

            throw error

        }

        return buffer.prefix(upTo: dataOutMoved)

    }

}
