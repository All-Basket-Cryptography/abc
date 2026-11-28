# Swift SHA-256

`AbcSha256Swift.Sha256` implements whole-byte SHA-256 directly in Swift. The library uses Swift standard-library arrays, fixed-width integer arithmetic, and bit operations. Apple CryptoKit supplies the independent oracle in the test target. [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

Use `Sha256.hash([UInt8])` for one-shot hashing. Streaming instances accept a full byte array or a validated slice. `digest()` returns a 32-byte snapshot while preserving the stream. Copies can be updated independently, and a rejected update preserves the state.

## Reproduction

Use Apple Swift 6.1.2 from Xcode 16.4, macOS 15, and Python 3.11 or later. [Xcode 16.4 release notes](https://developer.apple.com/documentation/xcode-release-notes/xcode-16_4-release-notes)

```sh
DEVELOPER_DIR=/Applications/Xcode_16.4.app/Contents/Developer \
  python3 -B src/crypto/hash/sha256/impl/swift/check.py --output .abc/sha256-swift-native
```

The checker builds a standalone release-mode SwiftPM library and runs three known answers, padding and block boundary cases, deterministic differential inputs and streaming snapshots, and checks for input validation and value semantics. The report records the actual Apple Swift target, macOS version, source and test digests, and comparison counts.

## Evidence scope

The local Windows workspace has no Swift toolchain. The dedicated hosted macOS workflow runs the compile and runtime check and retains the test report. Swift source-to-specification refinement remains open.
