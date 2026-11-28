# PBKDF2-HMAC-SHA-256

The RFC 8018 PBKDF2 construction uses HMAC-SHA-256 as its PRF. The API accepts
raw password and salt bytes, a nonzero 32-bit iteration count, and a positive
output length bounded by `(2^32 - 1) * 32` bytes. Callers own the output buffer.
[RFC 8018 § 5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2)

The block index is one-based and encodes four big-endian bytes. Each output
block is the XOR of the first PRF result and all successive PRF results up
to the requested iteration count. The last block is truncated as needed.
The Lean model represents the positive iteration count as one initial result
plus a natural number of additional rounds. The model covers the complete
functional result of the validated API. For every accepted call, Lean proves
that the block-by-block output equals RFC material truncated to the caller's
requested length. For every rejected call, it proves exact preservation of
caller output. The supporting theorems cover validation, one-based block
indices, 32-byte PRF results, rolling XOR, cross-block truncation and
long-password normalization. The axiom audit uses Lean 4.31.0.

Portable Rust initializes the HMAC context once per derivation and copies the
precompressed inner and outer contexts for each PRF. The HMAC feature
`prepared-key` exposes the copy operation. The native tests exercise both
key-state branches, published vectors and an independent OpenSSL-backed
long-password vector. The exact Rust-to-Lean connection for the derive loop
and context copying, caller work limits, secret erasure and target-specific
timing evidence remain open.

The Rust test reproduces the published two-block PBKDF2 examples, including
the 80,000-iteration example. [RFC 7914 § 11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11) · [NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final)
```sh
python src/lean/check.py pbkdf2
cargo +1.92.0 test --locked --offline --manifest-path tools/build/rust/Cargo.toml -p abc-pbkdf2-hmac-sha256
cargo +1.92.0 run --release --locked --offline --manifest-path tools/build/rust/Cargo.toml -p abc-pbkdf2-hmac-sha256 --example benchmark
```

On a local Windows x64 host using Rust 1.92.0 release builds, the benchmark
uses a 32-byte output and 4,096 iterations. Across nine measured calls, the
32-byte password median dropped from 3.401 ms at `aead74f` to 1.916 ms
with the prepared key. The 4,096-byte password medians were 3.405 ms and
1.916 ms. These are within-project observations for two public inputs.
