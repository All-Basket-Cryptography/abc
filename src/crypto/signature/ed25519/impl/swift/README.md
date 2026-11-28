# Strict Ed25519 in Swift

`AbcEd25519Swift` provides pure Ed25519. Apple CryptoKit derives a
32-byte compressed public key from a 32-byte seed. OpenSSL 3.5 EVP
produces the profile's deterministic 64-byte signatures. Invalid seed
widths throw. `verifyStrict` returns false on a rejected public key or
signature.
[OpenSSL Ed25519](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ED25519/)

Verification checks a canonical scalar `S < L` and a canonical
compressed `y < p` for each of the public key A and commitment R. It
rejects all small-order points, including malformed x-signs for x=0,
and checks the public Edwards curve equation via Euler's criterion.
CryptoKit evaluates the signature equation. The small-order check
permits mixed-order encodings to reach the provider.
[RFC 8032 §§5.1.2–5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.2) ·
[Apple Curve25519.Signing](https://developer.apple.com/documentation/cryptokit/curve25519/signing)

The offline SwiftPM consumer checks 99 exact matches with OpenSSL,
including three RFC examples, and 12 invalid encodings in both A and R.
The existing Lean model covers field constants, the scalar bound and
a mathematical cofactor schedule. Complete Swift field refinement and
provider source and compiled-target proofs remain open.
[Lean Ed25519 model](../java/Ed25519JvmModel.lean)

Use Xcode 16.4, Swift 6.1.2 and Node on macOS arm64. Set
`PKG_CONFIG_PATH` to the OpenSSL 3.5 library's pkg-config directory.

```sh
python -B src/crypto/agreement/x25519/impl/swift/check.py ed25519
```
