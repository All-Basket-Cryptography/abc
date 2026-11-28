# Deterministic ECDSA P-256/SHA-256 in C11

Build `abc_ecdsa_p256_sha256_c.c` and `ecdsa_p256_nonce.c` with
OpenSSL development headers and link libcrypto. Include the public
header `abc_ecdsa_p256_sha256_c.h`.

The private key is a 32-byte big-endian scalar in `1..n-1`.
Public key derivation emits a 65-byte uncompressed SEC 1 point.
Verification accepts compressed and uncompressed SEC 1 points with exact
widths and verifies both S representatives. The signature is 64 bytes
in IEEE P1363 order `r || s`, with the original RFC 6979 S value.
[RFC 6979 Appendix A.2.5](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5) · [P-256 domain parameters](https://csrc.nist.gov/pubs/sp/800/186/final)

The C engine hashes the message with SHA-256 and advances the RFC 6979
HMAC-SHA-256 state for each rejected candidate, including zero `r` or
`s`. OpenSSL supplies SHA-256, HMAC, EC and fixed-nonce ECDSA
arithmetic. Nonce inversion uses fixed-exponent Montgomery
exponentiation modulo the prime group order. The adapter never supplies
a random nonce. It stops after 128 candidates with an explicit error
and preserves the signature destination. Test-only hooks let the
verifier exercise the mathematical `s=0` case and compare the retry
state with an independent HMAC transcription.
[RFC 6979 §3.2](https://www.rfc-editor.org/rfc/rfc6979.html#section-3.2) · [OpenSSL 3.5.4 ECDSA arithmetic](https://github.com/openssl/openssl/blob/openssl-3.5.4/crypto/ec/ecdsa_ossl.c)

Windows x64 Clang 21.1.8 Release and UBSan adapter builds passed the
two RFC signatures, the RFC public key, 48 bidirectional Node/OpenSSL
comparisons, three candidate rejection checks and three retry-state
comparisons. The test also verifies malformed SEC 1 points, out-of-range
scalars, alternate S representatives, altered messages, and the absence
of test hooks from the production-shaped build.

Set `ABC_OPENSSL_INCLUDE` to the installed OpenSSL development
include directory. The tested Git for Windows OpenSSL 3.5.4 binary
had SHA-256 `9325e8486c61b3227abeacf635279a10b828a3b39bc1124a6b5159ae00174181`.
Provider arithmetic uses the documented low-level OpenSSL API.
Source refinement including the provider internals, compiled-target
timing, complete key erasure and FIPS qualification remain open.
[FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final)

```sh
python -B src/crypto/signature/ecdsa-p256-sha256/impl/c/check.py
python -B src/crypto/signature/ecdsa-p256-sha256/impl/c/check.py --ubsan
```
