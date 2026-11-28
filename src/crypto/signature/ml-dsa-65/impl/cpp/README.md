# ML-DSA-65 for C++17

Compile `ml_dsa_65.cpp` with the OpenSSL development headers
and link libcrypto. The C++ adapter uses the OpenSSL default provider
for cryptographic computation.

The API uses a 32-byte seed, a 1,952-byte public key and a 3,309-byte
signature. It accepts arbitrary message bytes and a binary context up
to 255 bytes. It selects Pure ML-DSA and configures the OpenSSL
deterministic signing mode. Key derivation and signatures are staged
until the provider succeeds. Compile with `ABC_MLDSA65_TESTING` to
expose the expanded-key entry point used in ACVP checks.
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) · [OpenSSL ML-DSA signing](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)

The verifier matches the public-key digest and every signature byte in
the selected keyGen and sigGen cases and the two sigVer outcomes. It
also checks four seed-based sign and verify flows, repeated signatures,
empty messages, the 255-byte context boundary and unchanged output on
rejected parameters. A separate production-shaped build exercises
the public entry points and confirms the expanded-key test entry
point is absent.
[Pinned NIST vectors](../../spec/acvp-fips204-sample.json)

The provider implementation owns the rejection loop and key data.
In OpenSSL 3.5.4, the signing loop advances its sampler counter with
no explicit exhaustion cap. Proof of counter exhaustion behavior,
source refinement, complete erasure, compiled timing and production
qualification remain open.
[OpenSSL 3.5.4 signing source](https://github.com/openssl/openssl/blob/openssl-3.5.4/crypto/ml_dsa/ml_dsa_sign.c)

Windows x64 Clang 21.1.8 Release and UBSan adapter checks passed
against Git for Windows OpenSSL 3.5.4, SHA-256
`9325e8486c61b3227abeacf635279a10b828a3b39bc1124a6b5159ae00174181`.
Set `ABC_OPENSSL_INCLUDE` to the matching development include
directory. An explicitly fingerprinted OpenSSL 3.x build can be
selected by passing `--openssl-dll` and `--dll-sha256`.

```sh
python -B src/crypto/agreement/ml-kem-768/impl/cpp/check.py dsa
python -B src/crypto/agreement/ml-kem-768/impl/cpp/check.py dsa --ubsan
```
