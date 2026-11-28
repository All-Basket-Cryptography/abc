# C++17 Argon2id v1.3

Include `argon2id.hpp` to derive a raw Argon2id tag through
the OpenSSL default provider. The adapter supplies the original memory
request, pass count, lane count, optional secret and associated data,
and explicitly selects version 0x13. The adapter uses one execution
thread while leaving the logical lane count unchanged.
[RFC 9106 §§3.1–3.2](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.1)

The supplied byte budget bounds the requested memory matrix. The
provider owns that allocation and uses additional storage for its
context and temporary data. Callers set their CPU, memory and tag
limits before accepting external parameters. The adapter checks positive
passes, RFC lane and memory bounds, a salt of at least eight bytes and
a tag of at least four bytes. It writes the tag only after the provider
succeeds and clears the staged tag. The provider handles its internal
matrix and zeroization.

Build `argon2id.cpp` against OpenSSL development headers and link
libcrypto. The Windows x64 qualification used OpenSSL 3.5.4
with Clang 21.1.8 and required the Git for Windows libcrypto SHA-256
`9325e8486c61b3227abeacf635279a10b828a3b39bc1124a6b5159ae00174181`.
Set `ABC_OPENSSL_INCLUDE` to the matching installed include directory.
The verifier can qualify an explicitly selected later OpenSSL 3.x
build using `--openssl-dll` and `--dll-sha256`. Its sanitizer run
instruments the ABC adapter and test consumer.
[OpenSSL 3.5 provider](https://docs.openssl.org/3.5/man7/EVP_KDF-ARGON2/) · [MSYS2 development package](https://packages.msys2.org/base/mingw-w64-openssl)

Release and UBSan passed the RFC 9106 §5.3 tag and 109 additional
cases through Node 24.12.0. The Release run also matched the independent
first-party Go implementation for these fixtures. The suite exercises
non-aligned requests, 1–4 lanes, repeated passes, a second addressing
batch, tag lengths from 4 to 257 bytes and output preservation on
preflight rejection. Formal refinement of the provider, its compiled
timing and memory-lifetime analysis remain open.
[Lean memory and index bounds](../../spec/Argon2idBounds.lean)

```sh
python -B src/crypto/kdf/argon2id/impl/c/check.py --language cpp --go-oracle
python -B src/crypto/kdf/argon2id/impl/c/check.py --language cpp --ubsan
```
