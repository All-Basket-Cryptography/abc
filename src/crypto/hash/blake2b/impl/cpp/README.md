# Portable C++ BLAKE2b

Compile `blake2b.cpp` as C++17 and include `blake2b.hpp`. The module
implements the sequential, unkeyed RFC 7693 profile for digest sizes
from 1 to 64 bytes. The digest length is part of the parameter block,
and the two 64-bit counter words encode the number of message bytes at
the end of each block. Each complete last block stays pending until
the caller adds more input or reads the digest. The one-shot and
streaming paths use the same 12-round compression function and fixed
storage. [RFC 7693 §§2–3](https://www.rfc-editor.org/rfc/rfc7693.html#section-2)

`Hasher` starts with a 64-byte digest. `reset(size)` selects the digest
size for a new stream, and `reset()` clears the stream while keeping
its configured size. `update` accepts a null pointer for zero bytes.
`digest` writes a snapshot to a non-null output buffer of exactly the
configured size. Subsequent updates extend the same stream. `hash`
uses its output length as the digest size and supports overlapping
one-shot input and output. Buffers must be valid for their declared
length and lie outside the stream context. Serialize access to a
shared context. Errors preserve the context and output buffer.

```cpp
#include "blake2b.hpp"

std::array<std::uint8_t, 32> digest{};
const std::array<std::uint8_t, 3> input{'a', 'b', 'c'};
const auto status = abc::native_blake2b::hash(input.data(), input.size(),
                                           digest.data(), digest.size());
```

On Windows x64, Clang 21.1.8 passed five published known answers,
139 OpenSSL 3.0.21 comparisons, 697 CPython 3.13.14 `hashlib.blake2b`
comparisons covering the remaining digest sizes, 841 prefix snapshot
cases and 4,926 two-chunk splits. Both the release build with warnings
as errors and the UndefinedBehaviorSanitizer build passed buffer,
counter carry and overflow, reset and overlap checks. The 1 MiB
BLAKE2b-512 throughput medians on an Intel Core i7-12700K were 1,133
MiB/s for the native C++ core and 1,169 MiB/s for OpenSSL through
CPython. [RFC 7693 Appendix A](https://www.rfc-editor.org/rfc/rfc7693.html#appendix-A) · [BLAKE2 project known answers](https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json)

```sh
python -B src/crypto/hash/blake2b/impl/cpp/check.py
python -B src/crypto/hash/blake2b/impl/cpp/check.py --ubsan
python -B src/crypto/hash/blake2b/impl/cpp/check.py --benchmark
```

Lean proves the final-block layout, including retention of a complete
final block. The remaining work is C++ source refinement for
parameter encoding, counters, compression and streaming equivalence,
plus timing analysis on compiled targets. The BLAKE2 design paper
describes the algorithm's design choices and security analysis.
[Lean buffer model](../../spec/Blake2bBuffer.lean) · [BLAKE2 design paper](https://www.blake2.net/blake2_lncs.pdf)
