# ChaCha20 in C++

Compile `chacha20.cpp` as C++17 and include `chacha20.hpp`. The
`abc::native_chacha20` namespace provides fixed-width `Key`, `Nonce`
and `Block` types. `stream_block` emits a 64-byte block. `apply` writes
the equally long destination prefix.

The source permits partial or exact input/output overlap and checks the
output capacity and remaining counter domain before writing. Use a
unique nonce under each key. A separate aligned call advances the
counter by the number of 64-byte blocks already consumed.

Tests check two RFC answers, the final counter, aliasing, error
preservation and 144 independent OpenSSL 3.5.4 ciphertexts. The
repository's Lean specification checks the counter domain and
quarter-round equations.

The Windows x64 Clang 21.1.8 release and UBSan runs passed. Lean 4.31.0
checks that the eight extracted `quarter_round` statements compute
the RFC result on four distinct 32-bit unsigned words. The restricted
translation models assignments, addition, XOR and the exact shift
expression of the rotation helper. Whole-function source refinement,
memory safety and compiled-target leakage require further evidence.
[RFC 8439 §§2.1–2.4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.1) · [ChaCha design paper](https://cr.yp.to/chacha/chacha-20080128.pdf) · [Lean counter model](../../spec/ChaCha20Counter.lean)

On the Intel Core i7-12700K test host, the medians were
88 ns for 64 bytes and 4987 ns for 4 KiB.
The native harness measures five batches of 1,024 calls with the
test bridge inside the timer.

In a Visual Studio developer shell on Windows, run from the
repository root with Python and Clang. Node provides the independent OpenSSL comparisons.

```sh
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language cpp --profile chacha20
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language cpp --profile chacha20 --ubsan
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language cpp --profile chacha20 --benchmark
python -B src/crypto/cipher/chacha20/impl/c/quarter_round_proof.py --language cpp
```
