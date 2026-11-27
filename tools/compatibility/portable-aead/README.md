# Portable AEAD interoperability and measurement

The command below compares the exact Rust AES-256-GCM and
ChaCha20-Poly1305 profile with Node's OpenSSL-backed implementation. It
checks complete ciphertexts and tags for 348 public cases. The Rust
harness independently opens each admitted output. Cases cover empty,
partial-block, exact-block, and multiblock payload or associated data.

```sh
node tools/compatibility/portable-aead/check.mjs
node tools/compatibility/portable-aead/check.mjs --benchmark
```

The optional measurement includes one warm-up followed by nine batches
of 64 seal operations per method and length. The Rust release API uses a
mutable buffer and includes the copy into that buffer. The Node API
includes binding and allocation overhead. Both use 16 bytes of associated
data, generated public inputs and distinct test nonces within each run.
These figures are local interface comparisons.

| Method and input | Rust 1.92.0 median | Node 24.12.0 / OpenSSL 3.5.4 median |
| --- | ---: | ---: |
| AES-256-GCM, 64 bytes | 68.3 µs | 4.42 µs |
| AES-256-GCM, 4 KiB | 2.83 ms | 5.84 µs |
| ChaCha20-Poly1305, 64 bytes | 0.235 µs | 3.28 µs |
| ChaCha20-Poly1305, 4 KiB | 7.17 µs | 6.70 µs |

Measured on a shared Windows x64 host with an Intel Core i7-12700K.
Compiled-code leakage and other CPUs or interfaces require separate measurements.
