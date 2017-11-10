# Crypto

Crypto is an easy-to-use and type safe Swift wrapper for CommonCrypto.

## Requirements

- iOS 8 and later
- macOS 10.10 and later
- tvOS 9.0 and later
- watchOS 2.0 and later
- Swift 3.2 and later

## Installation

Crypto is available via Carthage.

### Carthage

To install Crypto using [Carthage](https://github.com/Carthage/Carthage), add this line to your `Cartfile`:

~~~
github "alexaubry/Crypto"
~~~

### CocoaPods

Crypto cannot be installed with Carthage yet. Please read [#1](https://github.com/alexaubry/Crypto/issues/1) for more information.

## Usage

Crypto supports the following operations:

- [Digests](#digests)
- [HMAC](#hmac)
- [Key Derivation - PBKDF2](#key-derivation)
- [Symmetric Key Wrap](#key-wrap)
- [Encryption / Decryption](#encryption-and-decryption)

### Digests

Use the `Digest` enum to compute the hash of messages.

~~~swift
let message: Data = "secret".data(using: .utf8)!
let hash = Digest.sha256.hash(message: message)
~~~

The `hash(message:)` method returns a `Data` object containing the hash.

> Available digests: `.md4`, `.md5`, `.sha1`, `.sha224`, `.sha256`, `.sha384`, `.sha512`

### HMAC

Use the `HMAC` enum to compute the HMAC for a given message and key.

~~~swift
let message: Data = "secret".data(using: .utf8)!
let key: Data = ...
let hmac = HMAC.sha256.authenticate(message: message, with: key)
~~~

The `authenticate(message:,with:)` method returns a `Data` object containing the HMAC code for the message.

> Available algorithms: `.sha1`, `.sha224`, `.sha256`, `.sha384`, `.sha512`

## Key Derivation

Use the `KeyDerivation` enum to calibrate and derive passwords with the `PBKDF2` algorithm.

## Key Wrap

Use the `SymmetricKeyWrap` enum to wrap and unwrap keys with an encryption key.

## Encryption and Decryption

Use the `Cryptor` enum to encrypt and decrypt data.

### Random Data

Two random data generators are available:

- `CommonRandom` - uses `CCRandomGenerateBytes` from CommonCrypto
- `SecRandom` - uses `SecRandomCopyBytes` from Security.framework

They both conform to the `Random` protocol.

**Example**:

~~~swift
let ccRandom: Data = try CommonRandom.generate(bytes: 32)
let secRandom: Data = try SecRandom.generate(bytes: 32)
~~~

This generates 32 bytes of random data. 

## Author

Written by Alexis Aubry. You can [find me on Twitter](https://twitter.com/_alexaubry).

## License

Crypto is available under the MIT license. See the [LICENSE](LICENSE) file for more info.