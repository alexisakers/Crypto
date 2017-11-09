/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import CommonCrypto

/**
 * Errors thrown by CommonCrypto operations.
 */

public enum CryptoError: Error {

    case illegalParameter
    case bufferTooSmall
    case memoryFailure
    case alignmentError
    case decodeError
    case overflow
    case rngFailure
    case callSequenceError
    case keySizeError
    case unimplemented
    case unspecifiedError
    case unknownError(CCStatus)
    case unknownStatus(OSStatus)

    init?(status: CCStatus) {

        let intStatus = Int(status)

        switch intStatus {
        case kCCSuccess: return nil
        case kCCParamError: self = .illegalParameter
        case kCCBufferTooSmall: self = .bufferTooSmall
        case kCCMemoryFailure: self = .memoryFailure
        case kCCAlignmentError: self = .alignmentError
        case kCCDecodeError: self = .decodeError
        case kCCOverflow: self = .overflow
        case kCCRNGFailure: self = .rngFailure
        case kCCCallSequenceError: self = .callSequenceError
        case kCCKeySizeError: self = .keySizeError
        case kCCUnimplemented: self = .unimplemented
        case kCCUnspecifiedError: self = .unspecifiedError
        default: self = .unknownError(status)
        }

    }

}

// MARK: - Equatable

extension CryptoError: Equatable {

    public static func == (lhs: CryptoError, rhs: CryptoError) -> Bool {

        switch (lhs, rhs) {
        case (.illegalParameter, .illegalParameter): return true
        case (.bufferTooSmall, .bufferTooSmall): return true
        case (.memoryFailure, .memoryFailure): return true
        case (.alignmentError, .alignmentError): return true
        case (.decodeError, .decodeError): return true
        case (.overflow, .overflow): return true
        case (.rngFailure, .rngFailure): return true
        case (.callSequenceError, .callSequenceError): return true
        case (.keySizeError, .keySizeError): return true
        case (.unimplemented, .unimplemented): return true
        case (.unspecifiedError, .unspecifiedError): return true
        case (.unknownError(let lStatus), .unknownError(let rStatus)): return lStatus == rStatus
        case (.unknownStatus(let lStatus), .unknownStatus(let rStatus)): return lStatus == rStatus
        default: return false
        }

    }

}
