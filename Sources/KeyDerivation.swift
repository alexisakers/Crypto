/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import CommonCrypto

/**
 * Key derivation algorithms.
 *
 * Use objects of this type to derive a key from a text password/passphrase.
 */

public enum KeyDerivation {

    /**
     * The pseudo-random algorithms supported by password-based key derivation.
     */

    public enum PseudoRandomAlgorithm {

        /// The HMAC-SHA-1 algorithm.
        case hmacSHA1

        /// The HMAC-SHA-224 algorithm.
        case hmacSHA224

        /// The HMAC-SHA-256 algorithm.
        case hmacSHA256

        /// The HMAC-SHA-384 algorithm.
        case hmacSHA384

        /// The HMAC-SHA-512 algorithm.
        case hmacSHA512

    }

    /**
     * The PBKDF2 algorithm, associated with a pseudorandom algorithm.
     */

    case pbkdf2(PseudoRandomAlgorithm)

}

// MARK: - Algorithm Properties

extension KeyDerivation {

    /// The raw algorithm identifier for CommonCrypto.
    fileprivate var algorithm: CCPBKDFAlgorithm {

        switch self {
        case .pbkdf2: return CCPBKDFAlgorithm(kCCPBKDF2)
        }

    }

}

extension KeyDerivation.PseudoRandomAlgorithm {

    /// The raw algorithm identifier for CommonCrypto.
    fileprivate var algorithm: CCPseudoRandomAlgorithm {

        switch self {
        case .hmacSHA1: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
        case .hmacSHA224: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
        case .hmacSHA256: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .hmacSHA384: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
        case .hmacSHA512: return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        }

    }

}

// MARK: - Computation

extension KeyDerivation {

    /**
     * Determine the number of PRF rounds to use for a specific delay on the current platform.
     *
     * - parameter passwordLength: The length of the text password in bytes.
     * - parameter saltLength: The length of the salt in bytes. Must be smaller than 133.
     * - parameter derivedKeyLen: The expected length of the derived key in bytes.
     * - parameter delay: The targetted duration we want to achieve for a key derivation with these
     * parameters, in milliseconds.
     *
     * - throws: In case of failure, this method throws `CryptoError.unspecifiedError`
     * - returns: The number of iterations to use for the desired processing time.
     */

    public func calibrate(passwordLength: Int, saltLength: Int, derivedKeyLength: Int, delay: UInt32) throws -> UInt32 {

        switch self {
        case .pbkdf2(let pseudoRandom):

            let result = CCCalibratePBKDF(algorithm, passwordLength, saltLength,
                                    pseudoRandom.algorithm, derivedKeyLength, delay)

            if result == UInt32.max {
                throw CryptoError.unspecifiedError
            }

            return result

        }

    }

    /**
     * Derive a key from a text password/passphrase.
     *
     * - parameter password: The text password used as input to the derivation function.
     * - parameter salt: The salt byte values used as input to the derivation function.
     * - parameter rounds: The number of rounds of the Pseudo Random Algorithm to use. It cannot be zero.
     * - parameter derivedKeyLength: The expected length of the derived key in bytes. It cannot be zero.
     *
     * - note:  The actual octets present in the password string will be used with no additional processing.
     * It's extremely important that the same encoding and normalization be used each time this routine
     * is called if the same key is  expected to be derived.
     *
     * - throws: In case of failure, this function throws a `CryptoError` object. Derivation can fail because
     * of invalid parameters.
     * - returns: A Data buffer containing the resulting derived key produced by the function.
     */

    public func derive(password: String, salt: Data, rounds: UInt32, derivedKeyLength: Int) throws -> Data {

        switch self {
        case .pbkdf2(let pseudoRandom):

            var buffer = Data(count: derivedKeyLength)

            let result = buffer.write(withPointerTo: salt) { bufferPtr, saltPtr in

                password.withCString { passwordPtr in

                    return CCKeyDerivationPBKDF(self.algorithm, passwordPtr, password.utf8.count,
                                                saltPtr, salt.count,
                                                pseudoRandom.algorithm,
                                                rounds,
                                                bufferPtr, derivedKeyLength)

                }

            }

            if let error = CryptoError(status: result) {
                throw error
            }

            return buffer

        }

    }

}
