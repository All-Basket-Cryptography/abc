# Poly1305 in C

Compile `abc_poly1305_c.c` as C11 and include `abc_poly1305_c.h`.
`abc_poly1305_c_authenticate` returns a tag for a complete message.
For streaming, allocate one `abc_poly1305_c_mac`, initialize it with
`abc_poly1305_c_init`, and call `abc_poly1305_c_update` and
`abc_poly1305_c_finish`. Keep input and output storage separate from
the context itself. Use `abc_poly1305_c_clear` when the state is no
longer needed.

Each distinct message requires a fresh 32-byte one-time key. Finalization
closes the stream, returns a fixed 16-byte tag and can be repeated.
Arithmetic uses five radix-`2^26` limbs, fixed-width multiplication,
and mask selection for the final reduction.

Tests cover eight RFC examples at all split points, 512 independent
integer comparisons and 32 direct OpenSSL 3.5.4 comparisons. The
repository's Lean arithmetic model gives reference bounds and
modular recurrence checks.

The Windows x64 Clang 21.1.8 release and UBSan runs passed. Source
refinement and compiled-target leakage evidence remain open.
[RFC 8439 §2.5 and Appendix A.3](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5) · [Poly1305 design paper](https://doi.org/10.1007/11502760_3) · [Lean arithmetic model](../go/Poly1305GoModel.lean)

On the Intel Core i7-12700K test host, the medians were
93 ns for 64 bytes and 1828 ns for 4 KiB.
The native harness measures five batches of 1,024 calls with the
test bridge inside the timer.

In a Visual Studio developer shell on Windows, run from the
repository root with Python and Clang. Pass the path to an OpenSSL executable to reproduce the direct
Poly1305 comparisons.

```sh
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language c --profile poly1305 --openssl <openssl-executable>
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language c --profile poly1305 --ubsan --openssl <openssl-executable>
python -B src/crypto/aead/chacha20-poly1305/impl/c/check.py --language c --profile poly1305 --benchmark
```
