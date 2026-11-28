# C++17 X25519

Include `x25519.hpp` to derive a raw 32-byte public key and
shared secret through the OpenSSL default provider. The provider clamps
the scalar, masks the top bit of the peer u-coordinate and accepts
the RFC noncanonical aliases tested here. The adapter rejects
all-zero agreement, clears the temporary secret and preserves the
caller’s output on failure. Supply fresh private material from a
cryptographic RNG and bind the result to the protocol transcript.
[RFC 7748 §§5–7](https://www.rfc-editor.org/rfc/rfc7748.html#section-5)

Build `x25519.cpp` against OpenSSL development headers and link
libcrypto. The Windows x64 qualification used OpenSSL 3.5.4
with Clang 21.1.8 and required the Git for Windows libcrypto SHA-256
`9325e8486c61b3227abeacf635279a10b828a3b39bc1124a6b5159ae00174181`.
Set `ABC_OPENSSL_INCLUDE` to the matching installed include directory.
The verifier can qualify an explicitly selected later OpenSSL 3.x
build using `--openssl-dll` and `--dll-sha256`. Its sanitizer run
instruments the ABC adapter and test consumer.
[OpenSSL 3.5 provider](https://docs.openssl.org/3.5/man7/EVP_PKEY-X25519/) · [MSYS2 development package](https://packages.msys2.org/base/mingw-w64-openssl)

Release and UBSan passed six RFC known answers, including the first
and thousandth ladder iterations. The suite also checks 196 Node
OpenSSL interface comparisons, 32 private clamp aliases, 14 low-order
peer rejections and overlapping buffers. Lean covers independent
field bounds. Adapter-to-provider refinement, compiled timing and
complete key-material erasure remain open.
[Lean carry bounds](../../spec/X25519CarryBounds.lean)

```sh
python -B src/crypto/agreement/x25519/impl/c/check.py --language cpp
python -B src/crypto/agreement/x25519/impl/c/check.py --language cpp --ubsan
```
