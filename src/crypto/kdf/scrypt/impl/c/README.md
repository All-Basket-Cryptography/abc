# C11 scrypt

Compile `abc_scrypt_c.c` with the C PBKDF2-HMAC-SHA-256 module. This
module implements Salsa20/8, BlockMix and ROMix in C and visits the
parallelization lanes serially. The PBKDF2 dependency uses ABC C HMAC
and the pinned HACL* SHA-256 core.
[RFC 7914 §§2–7](https://www.rfc-editor.org/rfc/rfc7914.html#section-2) · [C PBKDF2 module](../../../pbkdf2-hmac-sha256/impl/c/README.md)

`abc_scrypt_c_workspace_bytes` checks RFC and machine-size bounds and
returns `128 * r * (N + p + 1)` bytes. Allocate that many bytes for
the initial lanes, one reusable ROMix table and one BlockMix block.
The PBKDF2 dependency also allocates its output staging and HMAC
context. `abc_scrypt_c_derive` checks bounds, sizes and overlap before
changing either output buffer. Keep the used workspace prefix disjoint
from password, salt and output. The derived key may overlap the inputs.
The used workspace is zeroed when an admitted derivation returns.
Set deployment limits for CPU and memory before accepting parameters.

Windows x64 Clang 21.1.8 Release and UBSan trap runs passed the first
three RFC known answers, 144 OpenSSL 3.0.21 comparisons, and checks for
arithmetic overflow, short workspace, overlap, zeroization and guard
bytes. The fourth RFC vector uses a 1 GiB table. On an Intel
Core i7-12700K with `N=4096, r=8, p=1` and a 64-byte output, the
median of five four-derivation batches was 5.58 ms per derivation for C
with a reused workspace, and 8.90 ms for OpenSSL through CPython.
[RFC 7914 §12](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)

```sh
python -B src/crypto/kdf/scrypt/impl/c/check.py
python -B src/crypto/kdf/scrypt/impl/c/check.py --ubsan
python -B src/crypto/kdf/scrypt/impl/c/check.py --benchmark
```

ROMix addresses depend on the derived state, as specified in the RFC.
Lean checks table and BlockMix index bounds. Source refinement and
complete key-lifetime and compiled-target timing analysis remain open.
[Lean scrypt bounds](../../spec/ScryptBounds.lean)
