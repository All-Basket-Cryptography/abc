# C++17 scrypt

Compile `scrypt.cpp` together with the C++ PBKDF2-HMAC-SHA-256
module. Its C++ core implements Salsa20/8, BlockMix and ROMix. It
processes the parallelization lanes serially and calls ABC C++
PBKDF2 for the initial and final derivation.
[RFC 7914 §§2–7](https://www.rfc-editor.org/rfc/rfc7914.html#section-2) · [C++ PBKDF2 module](../../../pbkdf2-hmac-sha256/impl/cpp/README.md)

`workspace_bytes` checks `Parameters` and returns `128 * r * (N + p + 1)`
bytes. `derive` uses that workspace prefix for the initial lanes, a
reusable ROMix table and a BlockMix block. Keep the prefix disjoint
from the other buffers. Output can overlap the password or salt.
Preflight rejection preserves the output and workspace, and an
admitted derivation clears the used workspace on return. Set deployment
limits for CPU and memory before accepting parameters.

Windows x64 Clang 21.1.8 Release and UBSan trap runs passed the first
three RFC known answers, 144 OpenSSL 3.0.21 comparisons, and checks
for arithmetic overflow, short workspace, overlap, zeroization and
guard bytes. The fourth RFC vector uses a 1 GiB table.
On an Intel Core i7-12700K with `N=4096, r=8, p=1` and a 64-byte output,
the median of five four-derivation batches was 5.64 ms per derivation
for C++ with a reused workspace, and 9.06 ms for OpenSSL through
CPython.
[RFC 7914 §12](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)

```sh
python -B src/crypto/kdf/scrypt/impl/c/check.py --language cpp
python -B src/crypto/kdf/scrypt/impl/c/check.py --language cpp --ubsan
python -B src/crypto/kdf/scrypt/impl/c/check.py --language cpp --benchmark
```

ROMix uses state-dependent memory access from RFC 7914. Lean checks
table and BlockMix index bounds. Source refinement and complete
key-lifetime and compiled-target timing analysis remain open.
[Lean scrypt bounds](../../spec/ScryptBounds.lean)
