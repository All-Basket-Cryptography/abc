# Deterministic ECDSA P-256/SHA-256 in Python

`abc_ecdsa_p256.py` signs through the ABC C engine. That engine advances
the RFC 6979 HMAC state after a rejected nonce or a zero signature
scalar. It reports an error if all 128 candidates are rejected.
The pinned `cryptography` wheel supplies public-key derivation and
verification. Its OpenSSL 4.0.3 deterministic signing path does not
advance the RFC 6979 state after a zero signature scalar.
[C signing engine](../c/README.md) · [RFC 6979 §3.2](https://www.rfc-editor.org/rfc/rfc6979.html#section-3.2) · [OpenSSL 4.0.3 ECDSA signing source](https://github.com/openssl/openssl/blob/openssl-4.0.3/crypto/ec/ecdsa_ossl.c)

The private scalar is a 32-byte big-endian value in `1..n-1`.
`public_key` returns the 65-byte uncompressed SEC 1 encoding and
`verify` accepts compressed or uncompressed SEC 1 points. `sign`
returns a 64-byte IEEE P1363 `r || s` signature and preserves the
original S representative.
[RFC 6979 Appendix A.2.5](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5)

On Windows x64, install the pinned [Python wheels](../../../../providers/python/README.md)
and set `ABC_OPENSSL_INCLUDE` to the OpenSSL development headers that
match the libcrypto build. Run the checker from the repository root
with Clang, `llvm-dlltool` and Node on `PATH`. `--output` keeps the two
verified libraries together in the selected directory. The checker
fingerprints the OpenSSL dependency. An explicitly selected later
provider can be supplied with `--openssl-dll` and `--dll-sha256`.

```powershell
python -B src/crypto/signature/ecdsa-p256-sha256/impl/python/check_native.py --output .abc/ecdsa-python-native
$env:ABC_ECDSA_P256_LIBRARY = (Resolve-Path '.abc/ecdsa-python-native/abc_ecdsa_p256_sha256_c.dll').Path
python -B -m unittest discover -s src/crypto/signature/ecdsa-p256-sha256/impl/python
```

Set `ABC_ECDSA_P256_LIBRARY` to the absolute path of the build in a
trusted directory, or construct `DeterministicSigner` with that path
and call its `sign` method. Public key derivation and verification
can be used without loading the signing engine. The Python SDK is
distributed as source and the signing library is built for the target.

The verifier checks both RFC signatures, 48 bidirectional Node/OpenSSL
cases, unchanged input semantics, and signer configuration. The
optional `--rust-oracle` uses the offline RustCrypto example to verify
and reproduce all 48 exact signatures. `--ubsan` instruments the C
adapter. The C engine suite separately exercises candidate rejection
and the retry state. Compiled-target leakage, full source refinement
and retention of key bytes by the Python runtime remain outside this
evidence.
[C retry checks](../c/README.md) · [RustCrypto profile](../../spec/README.md)
