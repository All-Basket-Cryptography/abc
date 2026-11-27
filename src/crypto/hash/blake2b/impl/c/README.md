# Portable C BLAKE2b

Compile `abc_blake2b_c.c` as C11 and include `abc_blake2b_c.h`. The
module implements sequential, unkeyed BLAKE2b with a 1–64-byte digest.
The parameter word binds the digest size at initialization. The
12-round compression function consumes little-endian words and a
128-bit byte count. A complete last block stays pending for the final
flag. The module uses fixed storage and has no provider dependency.
[RFC 7693 §§2–3](https://www.rfc-editor.org/rfc/rfc7693.html#section-2)

Call `abc_blake2b_c_init` before using a context. The same call resets
a stream and sets its digest size. `abc_blake2b_c_update` accepts a
null input pointer for zero bytes. `abc_blake2b_c_digest` snapshots the
digest and leaves the stream open for more input. Pass a writable
output buffer of exactly the configured size. Streaming buffers must
be valid for their declared lengths and lie outside the context.
Serialize operations on a shared context. The `abc_blake2b_c_hash`
one-shot API selects its digest size from the output length, and
permits overlapping input and output. Errors preserve the context
and output buffer.

```c
#include "abc_blake2b_c.h"

int digest_message(const uint8_t *input, size_t length, uint8_t output[32]) {
    return abc_blake2b_c_hash(input, length, output, 32);
}
```

Windows x64 Clang 21.1.8 passed five published known answers, 139
OpenSSL 3.0.21 comparisons, 697 CPython 3.13.14 `hashlib.blake2b`
comparisons, 841 prefix snapshots and 4,926 two-chunk splits. Both
the release build with warnings as errors and the UBSan trap build
passed. The suite checks `2^128 - 1` byte boundary arithmetic,
context and output preservation on errors, and buffer overlap. It
shares only the reference test data generator with the C++ module.
[RFC 7693 Appendix A](https://www.rfc-editor.org/rfc/rfc7693.html#appendix-A) · [BLAKE2 project known answers](https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json)

On an Intel Core i7-12700K, the same-host 1 MiB BLAKE2b-512 throughput
medians were 1,092 MiB/s for C and 1,165 MiB/s for OpenSSL, both
invoked from CPython.

```sh
python -B src/crypto/hash/blake2b/impl/c/check.py
python -B src/crypto/hash/blake2b/impl/c/check.py --ubsan
python -B src/crypto/hash/blake2b/impl/c/check.py --benchmark
```

Lean proves retention of the final block in the buffer model. C
source refinement for the parameter encoding, counter, compression
and stream equivalence remains open, as does compiled-target timing
analysis. The original paper describes the algorithm design and its
security analysis.
[Lean buffer model](../../spec/Blake2bBuffer.lean) · [BLAKE2 design paper](https://www.blake2.net/blake2_lncs.pdf)
