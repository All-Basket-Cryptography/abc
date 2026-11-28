# Portable C++ SHAKE256

Compile `shake256.cpp` and the repository's portable C++ Keccak object
and link them with a consumer of `shake256.hpp`. `Hasher::update`
absorbs bytes. `Hasher::finalize` returns an independent reader while
leaving the absorber available for later updates. `Reader::read`
fills a caller-sized buffer and continues the same stream on each
call. One-shot `xof` accepts overlapping input and output. Empty
buffers may be null. Pass valid buffers outside each context and
serialize operations on a shared context.
[C++ Keccak core](../../../keccak-p1600/impl/cpp/README.md)

This byte-oriented profile uses the FIPS 202 SHAKE domain delimiter
`0x1f`, a 136-byte rate and pad10*1. Lengths within one operation use
`size_t` and the reader maintains only its position in the current
rate block. Lean checks the encoding, finite-stream reads, and the
table model. C++ implementation refinement and production qualification
remain open.
[FIPS 202 §§5 and 6.2](https://csrc.nist.gov/pubs/fips/202/final) · [SHAKE encoding model](../../spec/Shake256Encoding.lean)

Windows x64 Clang 21.1.8 passed three known answers, 179 OpenSSL
comparisons, 182 snapshots and 4,176 input and output split checks.
The same cases passed with UndefinedBehaviorSanitizer. On a Core
i7-12700K, the local throughput medians for 1 MiB of input and a 4 KiB
output were 535 MiB/s for the C++ implementation and 660 MiB/s for
OpenSSL through CPython.
[NIST empty message](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf) · [NIST 1600-bit message](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg1600.pdf)

```sh
python -B src/crypto/hash/keccak-p1600/impl/cpp/check.py shake256
python -B src/crypto/hash/keccak-p1600/impl/cpp/check.py shake256 --ubsan
python -B src/crypto/hash/keccak-p1600/impl/cpp/check.py shake256 --benchmark
```
