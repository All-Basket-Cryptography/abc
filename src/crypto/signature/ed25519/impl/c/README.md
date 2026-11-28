# Strict Ed25519 for C11

Compile `abc_ed25519_c.c` with the OpenSSL development headers
and link libcrypto. The API takes a 32-byte seed, derives a 32-byte
public key and signs the supplied bytes in Pure Ed25519 mode. It
emits a 64-byte RFC signature. Verification checks that the public key
and signature commitment have canonical compressed y-coordinates and
rejects all eight points of the cofactor subgroup. The OpenSSL
default provider checks curve decoding, the canonical scalar and the
strict verification equation.
[RFC 8032 §§5.1.3 and 5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7) · [OpenSSL Ed25519](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ED25519/)

On Windows x64, Clang 21.1.8 Release and UBSan passed three RFC
known answers, 40 Node/OpenSSL interface cases and 22 strict encoding
rejections. The latter exercises the eight torsion points as both
public keys and commitments, noncanonical encodings and out-of-range
scalars. The verifier also checks exact signature bytes, altered
messages, aliasing and output preservation on error.
[RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1)

The linked provider was Git for Windows OpenSSL 3.5.4,
SHA-256 `9325e8486c61b3227abeacf635279a10b828a3b39bc1124a6b5159ae00174181`.
Set `ABC_OPENSSL_INCLUDE` to its development headers. Substitute an
explicitly fingerprinted newer provider with `--openssl-dll` and
`--dll-sha256`. The sanitizer covers the adapter and consumer.
Source refinement, compiled-target timing and complete key erasure
remain open.
[OpenSSL 3.5.4 verification source](https://github.com/openssl/openssl/blob/openssl-3.5.4/crypto/ec/curve25519.c)

```sh
python -B src/crypto/signature/ed25519/impl/c/check.py
python -B src/crypto/signature/ed25519/impl/c/check.py --ubsan
```
