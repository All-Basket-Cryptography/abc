# AES-256-GCM in Swift

`AbcAes256GcmSwift` provides detached AEAD over Foundation `Data` with
a 32-byte key, a 12-byte nonce and a 16-byte tag. Apple CryptoKit
provides sealing and authenticated opening. Use a nonce unique to the key.
[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) ·
[Apple CryptoKit AES.GCM](https://developer.apple.com/documentation/cryptokit/aes/gcm)

`open` returns nil on authentication failure. Invalid sizes throw and
`openInto` commits only the authenticated plaintext prefix. The
independent SwiftPM consumer checks two published known answers,
272 OpenSSL cases and 77 authentication failures that preserve output.
The 4 KiB seal and open benchmark includes direct CryptoKit measurements.

The Lean model covers the fixed profile's length and counter bounds.
Complete refinement of CryptoKit, compiled timing and runtime key
erasure remain open.
[AES-GCM bounds](../../spec/Aes256GcmBounds.lean)

Run with Xcode 16.4, Swift 6.1.2, and Node/OpenSSL on macOS arm64.

```sh
python -B src/crypto/cipher/aes256/impl/swift/check.py aes256-gcm --benchmark
```
