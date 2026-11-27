# PBKDF2-HMAC-SHA-256

The RFC 8018 PBKDF2 construction uses HMAC-SHA-256 as its PRF. The API accepts
raw password and salt bytes, a nonzero 32-bit iteration count, and a positive
output length bounded by `(2^32 - 1) * 32` bytes. Callers own the output buffer.
[RFC 8018 § 5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2)

The block index is one-based and encodes four big-endian bytes. Each output
block is the XOR of the first PRF result and all successive PRF results up
to the requested iteration count. The last block is truncated as needed.
The Lean model represents the positive iteration count as one initial result
plus a natural number of additional rounds. Its checked lemmas establish the
rolling-accumulator equation independently of the PRF, as well as block index
and salt bounds.

The Rust test reproduces the published two-block PBKDF2 examples, including
the 80,000-iteration example. The exact Rust-to-Lean refinement, caller work
limits, secret erasure and target-specific timing evidence remain open.
[RFC 7914 § 11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)
```sh
python src/lean/check.py pbkdf2
cargo +1.92.0 test --locked --offline --manifest-path tools/build/rust/Cargo.toml -p abc-pbkdf2-hmac-sha256
```
