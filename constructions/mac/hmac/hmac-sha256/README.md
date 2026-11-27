# HMAC-SHA-256

Research tag generation over the ABC SHA-256 implementation. Use `authenticate`
for a complete byte slice or `HmacSha256` for streaming input. The output is a
caller-owned 32-byte tag. The module's evidence covers tested functional
behavior. Formal refinement, secret-memory handling, timing behavior, and
production review are pending.

Run `cargo +1.92.0 test --manifest-path build/rust/Cargo.toml --locked -p abc-hmac-sha256` from the repository root.
The vectors use [RFC 4231 sections 4.2, 4.3, and 4.7](https://www.rfc-editor.org/rfc/rfc4231.html#section-4).
