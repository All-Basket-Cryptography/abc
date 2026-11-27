# Portable C++ SHA3-256

Compile `sha3_256.cpp` and the repository's portable C++ Keccak object
and link them with a consumer of `sha3_256.hpp`. `Hasher::update` adds
bytes. `Hasher::digest` returns a 32-byte snapshot without closing the
stream. `reset` opens a fresh stream. `hash` supports overlapping
one-shot input and digest buffers. A null pointer is accepted for zero
bytes. Nonempty buffers must be valid for their declared length and
outside the stream context. Serialize operations on a shared context.
[C++ Keccak core](../../../keccak-p1600/impl/cpp/README.md)

This byte-oriented profile uses the FIPS 202 SHA3 domain delimiter
`0x06`, a 136-byte rate, pad10*1 and a 32-byte digest. It has a fixed
stack footprint for one-shot hashes. Lean checks the independent
encoding and table models. C++ implementation refinement and
compiled-target analysis remain open.
[FIPS 202 §§5 and 6.1](https://csrc.nist.gov/pubs/fips/202/final) · [SHA3 encoding model](../../spec/Sha3Encoding.lean)

Windows x64 Clang 21.1.8 passed three known answers, 149 OpenSSL
comparisons, 152 snapshots and 3,030 streaming split checks. It also
passed the same cases under UndefinedBehaviorSanitizer. On a Core
i7-12700K, the local 1 MiB throughput medians were 532 MiB/s for the C++
implementation and 657 MiB/s for OpenSSL through CPython.
[NIST empty message](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg0.pdf) · [NIST 1600-bit message](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg1600.pdf)

```sh
python -B src/crypto/hash/keccak-p1600/impl/cpp/check.py sha3-256
python -B src/crypto/hash/keccak-p1600/impl/cpp/check.py sha3-256 --ubsan
python -B src/crypto/hash/keccak-p1600/impl/cpp/check.py sha3-256 --benchmark
```
