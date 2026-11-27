# Portable C SHA3-256

Use `abc_sha3_256_c_init` before updating a caller-owned context.
`abc_sha3_256_c_update` absorbs bytes and `abc_sha3_256_c_digest`
writes a non-destructive 32-byte snapshot. One-shot
`abc_sha3_256_c_hash` permits overlap between input and output.
The digest operations require at least 32 output bytes and reject
short buffers before writing. Empty input may be null. Nonempty
input and output must refer to valid buffers outside the context.
Serialize calls on each context.
[C Keccak core](../../../keccak-p1600/impl/c/README.md)

The native C profile uses a 136-byte rate, the SHA3 delimiter
`0x06` and pad10*1. The encoding model records the mathematical
padding and digest convention. Complete C source refinement and
compiled-target qualification remain open.
[FIPS 202 §§5 and 6.1](https://csrc.nist.gov/pubs/fips/202/final) · [Mathematical model](../../spec/Sha3Encoding.lean)

On Windows x64, Clang 21.1.8 passed three known answers, 149
OpenSSL comparisons, 152 prefix snapshots and 3,030 split checks
in release and UBSan builds. Destination suffixes, overlap, reset
and rejected calls have their own checks. An i7-12700K measured
approximately 523 MiB/s for the C API and 655 MiB/s for OpenSSL
through CPython from the same 1 MiB input.
[NIST empty message](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg0.pdf) · [NIST 1,600-bit message](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA3-256_Msg1600.pdf)

```sh
python -B src/crypto/hash/keccak-p1600/impl/c/check.py sha3-256
python -B src/crypto/hash/keccak-p1600/impl/c/check.py sha3-256 --ubsan
python -B src/crypto/hash/keccak-p1600/impl/c/check.py sha3-256 --benchmark
```

Compile both `abc_sha3_256_c.c` and the shared C Keccak source when
linking a standalone application.
