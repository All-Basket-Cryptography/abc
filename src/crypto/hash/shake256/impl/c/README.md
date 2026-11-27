# Portable C SHAKE256

Use `abc_shake256_c_init` before calling `abc_shake256_c_update`.
`abc_shake256_c_finalize` snapshots the absorber into a caller-owned
reader. `abc_shake256_c_read` fills the requested output bytes and
advances that reader. One-shot `abc_shake256_c_xof` supports overlapping
input and output. A null buffer is allowed for zero bytes. Use valid
readable or writable buffers outside the context, and serialize access
to any one context or reader.
[C Keccak core](../../../keccak-p1600/impl/c/README.md)

This native C profile uses the FIPS SHAKE delimiter `0x1f`, pad10*1
and a 136-byte rate. It tracks the position within the current rate
block. The shared Lean model covers encoding and finite-stream
properties. Complete C source and compiled-target refinement remain
open.
[FIPS 202 §§5 and 6.2](https://csrc.nist.gov/pubs/fips/202/final) · [Encoding model](../../spec/Shake256Encoding.lean)

On Windows x64, Clang 21.1.8 passed three known answers, 179
OpenSSL comparisons, 182 prefix snapshots and 4,176 split checks
in release and UBSan builds. These checks include output over rate
boundaries, reset, buffer canaries and rejection that preserves reader
position. For 1 MiB of input and 4 KiB of output, a Core i7-12700K
measured about 525 MiB/s for this C API and 660 MiB/s for OpenSSL
through CPython.
[NIST empty message](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf) · [NIST 1,600-bit message](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg1600.pdf)

```sh
python -B src/crypto/hash/keccak-p1600/impl/c/check.py shake256
python -B src/crypto/hash/keccak-p1600/impl/c/check.py shake256 --ubsan
python -B src/crypto/hash/keccak-p1600/impl/c/check.py shake256 --benchmark
```

Compile both `abc_shake256_c.c` and the shared C Keccak source when
linking a standalone application.
