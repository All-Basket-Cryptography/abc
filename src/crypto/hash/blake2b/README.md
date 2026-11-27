# BLAKE2b in portable Rust

This `no_std` research implementation supports unkeyed sequential hashing with
digest sizes from 1 to 64 bytes. `Blake2b::new` binds the output length into the
parameter word before any input is processed. The streaming context keeps its
last block pending, even when it is exactly 128 bytes. `finalize` writes a
snapshot digest into an output slice of the configured size. `digest` uses its
output slice length as the requested size. The API checks the 128-bit byte
counter before mutating state and checks output capacity before writing bytes.
[RFC 7693 §§2–3](https://www.rfc-editor.org/rfc/rfc7693.html#section-2)

The test suite includes the RFC's `abc` example, different output-size domain
parameters, zero and full final blocks, every two-chunk split near 128 and 256
bytes, a synthetic counter overflow, and unchanged outputs on length errors.
The differential command checks both Rust entry paths with all 64 digest sizes
at nine message lengths using Python's `hashlib.blake2b` as an independent oracle.
[RFC 7693 Appendix A](https://www.rfc-editor.org/rfc/rfc7693.html#appendix-A)

```sh
cargo +1.92.0 test --manifest-path tools/build/rust/Cargo.toml --locked --offline -p abc-blake2b
python -B src/crypto/hash/blake2b/verify.py
```

Lean 4.31.0 checked the [buffer arithmetic](spec/Blake2bBuffer.lean) for a
retained final block. The lemmas cover lengths up to one block and exact block
multiples, with the final full block included in the pending bytes.

Keyed hashing, tree parameters, native acceleration, and source-level refinement
are outside the demonstrated scope. SDK and production qualification remain open.
