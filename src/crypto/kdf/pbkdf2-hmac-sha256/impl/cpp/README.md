# Portable C++17 PBKDF2-HMAC-SHA-256

This research core derives fixed-length byte strings using the independent
C++17 HMAC-SHA-256 core. A positive 32-bit iteration count is required.
The output must contain 1–`(2^32 - 1) × 32` bytes, and the salt limit
reserves four message bytes for the big-endian HMAC block index. The key is
normalized once and copied as keyed hash states across HMAC invocations.
[RFC 8018 § 5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2)

Admitted nonempty buffers must be valid for their declared sizes. Salt
and output must be disjoint. The caller sets limits on derivation work
before forwarding an iteration count or output length. Invalid pointers
or lengths detected at entry preserve the output.

Run `python -B src/crypto/kdf/pbkdf2-hmac-sha256/impl/cpp/check.py` with
Clang in the C++ developer environment. Clang 21.1.8 passed two RFC 7914
vectors, 45 Python/OpenSSL comparisons, and atomic boundary rejection on
Windows x64. Source-to-Lean
refinement, timing evidence, benchmarks and key-state erasure remain open.
[RFC 7914 § 11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)
