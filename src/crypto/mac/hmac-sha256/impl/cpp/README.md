# Portable C++17 HMAC-SHA-256

This research core uses the portable C++17 SHA-256 for key normalization and
both hash states. The one-shot function returns the full 32-byte tag.
`Hmac` starts with an empty key. Set a key before appending message bytes.
`digest()` returns a snapshot, and a successful `set_key` starts a new
message. Serialize access to each context.
[RFC 2104 § 2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2)

A pointer with an admitted nonzero length must point to that many readable
bytes outside the context. Null is valid with length zero. The key limit is
`2^61 - 1` bytes and the message limit is `2^61 - 1 - 64` bytes. The core
rejects larger lengths before reading input. Rejection preserves the context
or one-shot output.

Run `python -B src/crypto/mac/hmac-sha256/impl/cpp/check.py` from the repo
root with Clang and a C++17 standard library. On Windows use the x64
developer environment for compiler and linker paths. Clang 21.1.8 passed
three RFC 4231 vectors and 153 Python/OpenSSL HMAC comparisons on Windows
x64, including prefix snapshots, key buffer ownership and atomic null and
length rejection. Source-to-Lean refinement, compiler timing evidence,
benchmarks and key-state erasure remain open.
[RFC 4231 § 4](https://www.rfc-editor.org/rfc/rfc4231.html#section-4)
