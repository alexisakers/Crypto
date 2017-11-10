/**
 *  Crypto
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation

extension Data {

    mutating func write<T>(withPointerTo object: Data,
                           block: @escaping (UnsafeMutablePointer<UInt8>, UnsafePointer<UInt8>) throws -> T) rethrows -> T {

        return try self.withUnsafeMutableBytes { (mutablePtr: UnsafeMutablePointer<UInt8>) in

            try object.withUnsafeBytes { (objectPtr: UnsafePointer<UInt8>) in
                try block(mutablePtr, objectPtr)
            }

        }

    }

    mutating func write<T>(withPointerTo object1: Data,
                           _ object2: Data,
                           block: @escaping (UnsafeMutablePointer<UInt8>, UnsafePointer<UInt8>, UnsafePointer<UInt8>) throws -> T) rethrows -> T {

        return try self.withUnsafeMutableBytes { (mutablePtr: UnsafeMutablePointer<UInt8>) in

            try object1.withUnsafeBytes { (object1Ptr: UnsafePointer<UInt8>) in
                try object2.withUnsafeBytes { (object2Ptr: UnsafePointer<UInt8>) in
                    try block(mutablePtr, object1Ptr, object2Ptr)
                }
            }

        }

    }

    mutating func write<T>(withPointerTo object1: Data,
                           _ object2: Data,
                           _ object3: Data,
                           block: @escaping (UnsafeMutablePointer<UInt8>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, UnsafePointer<UInt8>) throws -> T) rethrows -> T {

        return try self.withUnsafeMutableBytes { (mutablePtr: UnsafeMutablePointer<UInt8>) in

            try object1.withUnsafeBytes { (object1Ptr: UnsafePointer<UInt8>) in
                try object2.withUnsafeBytes { (object2Ptr: UnsafePointer<UInt8>) in
                    try object3.withUnsafeBytes { (object3Ptr: UnsafePointer<UInt8>) in
                        try block(mutablePtr, object1Ptr, object2Ptr, object3Ptr)
                    }
                }
            }

        }

    }

}
