# Swift scrypt

`Scrypt.derive` implements RFC 7914 using the same-language PBKDF2 package,
Salsa20/8, BlockMix and a reusable ROMix table. It accepts a byte-array
password and salt, positive block and parallel factors, a power-of-two cost
and an explicit memory limit. `workspaceSize` measures the lane data, ROMix
table, two BlockMix arrays and 128 bytes of running state. The required limit
also includes the output. Swift and the PBKDF2 implementation have their own
allocation overhead.

ROMix makes password-dependent memory reads. The specified work arrays are
overwritten when derivation finishes. Swift optimizer and runtime behavior
need separate verification. The shared Lean model checks address and
permutation bounds. Exact Swift source refinement remains open.
[RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html) · [Shared proof scope](../../spec/README.md)

The release XCTest consumer checks two RFC vectors and 144 independent
OpenSSL cases, including acceptance of the exact buffer budget and rejection
of a budget one byte smaller.

```sh
export ABC_SCRYPT_FIXTURES="$PWD/.abc/scrypt-swift-fixtures.json"
mkdir -p .abc
python3 -B src/crypto/kdf/scrypt/impl/swift/make_fixtures.py "$ABC_SCRYPT_FIXTURES"
swift test --package-path src/crypto/kdf/scrypt/impl/swift/AbcScryptSwift --configuration release
```
