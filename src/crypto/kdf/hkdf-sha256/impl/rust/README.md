# HKDF-SHA-256

Research key derivation over the ABC HMAC-SHA-256 implementation. Call `derive`
for extract and expand in one step, or use `extract` and `Prk::expand` for
separate operations. The free `expand` accepts an existing pseudorandom key
of at least 32 bytes. Callers own the output buffer and choose its length.
Formal refinement, secret-memory handling, timing behavior, and production
review are pending.

Run `cargo +1.92.0 test --manifest-path tools/build/rust/Cargo.toml --locked -p abc-hkdf-sha256` from the repository root.
The vectors use [RFC 5869 appendix A.1–A.3](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A).
