# Poly1305 in C++

Compile `poly1305.cpp` as C++17 and include `poly1305.hpp`.
`abc::native_poly1305::authenticate` handles a complete message.
`Mac`, `update` and `finish` provide streaming. Use one `Mac` per message.
The state owns its input tail and clears its retained key-derived fields
at finalization and destruction.

Each distinct message requires a fresh 32-byte one-time key. Finalization
closes the stream, returns a fixed 16-byte tag and can be repeated.
Arithmetic uses five radix-`2^26` limbs, fixed-width multiplication,
and mask selection for the final reduction.
The block multiplier writes five explicit folded columns with cached
key multiples. [Paired Windows measurements](../../../../../../docs/status/poly1305-cpp-benchmark.json)

Tests cover eight RFC examples at all split points, 512 independent
integer comparisons and 32 direct OpenSSL 3.5.4 comparisons. The
repository's Lean arithmetic model gives reference bounds and
modular recurrence checks.

The Windows x64 Clang 21.1.8 release and UBSan runs passed. Source
refinement and compiled-target leakage evidence remain open.
[RFC 8439 §2.5 and Appendix A.3](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5) · [Poly1305 design paper](https://doi.org/10.1007/11502760_3) · [Lean arithmetic model](../go/Poly1305GoModel.lean)

On the Intel Core i7-12700K test host, the medians were
79 ns for 64 bytes and 1859 ns for 4 KiB.
The native harness measures five batches of 1,024 calls with the
test bridge inside the timer.

In a Visual Studio developer shell on Windows, run from the
repository root with Python and Clang. Pass the path to an OpenSSL executable to reproduce the direct
Poly1305 comparisons.

```sh
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language cpp --profile poly1305 --openssl <openssl-executable>
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language cpp --profile poly1305 --ubsan --openssl <openssl-executable>
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language cpp --profile poly1305 --benchmark
```
