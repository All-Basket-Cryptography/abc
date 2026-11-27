# Portable C SHA-512

The C11 implementation provides byte-oriented SHA-512 with caller-owned
storage and no heap allocation. Initialize a context with
`abc_sha512_c_init`, then call `abc_sha512_c_update` and
`abc_sha512_c_digest`. A digest is a non-destructive snapshot. The one-shot
`abc_sha512_c_hash` supports overlapping input and output. A destination of
at least 64 bytes receives exactly the first 64 bytes of the result, with
the remainder left untouched. A context must be initialized before use and
calls on that context must be serialized.

The compressor uses uint64 words, the 80-step SHA-512 schedule and explicit
big-endian loads. The two-word byte counter accepts messages up to
`2^125 - 1` bytes, converts the count to a 16-byte bit length, and rejects
an oversized update before changing the context.
[FIPS 180-4 §§4.2.3, 5.1.2, 5.2.2, 5.3.5, and 6.4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

Clang builds a shared library for a separate test consumer. The consumer
uses OpenSSL through CPython as its oracle and exercises streaming splits,
overlap, reset, padding and synthetic counter limits. Lean checks the
low-limb carry, fixed-width counter refinement, exact length guard and
unchanged counter on a modeled rejection. The repository's
[SHA-512 length lemmas](../../spec/Sha512Length.lean) cover padding and
encoding. End-to-end C source refinement and compiled-target assessment
remain open.
[NIST SHA-512 examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf)

```sh
python -B src/crypto/hash/sha512/impl/c/check.py
python -B src/crypto/hash/sha512/impl/c/check.py --ubsan
python -B src/crypto/hash/sha512/impl/c/check.py --benchmark
lean src/crypto/hash/sha512/impl/c/proof/Sha512LengthHalves.lean
```

Use a Visual Studio developer environment on Windows. Clang 21.1.8
passed four known answers, 152 OpenSSL comparisons, 156 prefix snapshots
and 3,166 split checks on Windows x64. The same cases passed with
UndefinedBehaviorSanitizer. On an Intel Core i7-12700K, a local benchmark
measured about 574 MiB/s for 1 MiB messages with the uninstrumented C
shared API and about 951 MiB/s with OpenSSL through CPython.
