# Portable C++17 HKDF-SHA-256

This research core implements extract, expand and derive using the native
C++17 HMAC-SHA-256 core. Extract produces 32 bytes and an empty salt uses
the RFC default. Expand accepts a PRK of 32 bytes or longer and derives
0–8160 bytes. The cumulative SHA-256 bound reserves room for the HMAC
pad, previous block and counter.
[RFC 5869 §§ 2.2–2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.2)

Nonempty admitted inputs and outputs must refer to actual buffers. Expand
and derive require disjoint info and output buffers, while output can
overlap PRK, salt or input keying material after those inputs have been
read. Rejected lengths and null pointers preserve the destination.

Run `python -B src/crypto/kdf/hkdf-sha256/impl/cpp/check.py` with Clang in
the C++ developer environment. Clang 21.1.8 passed RFC 5869 cases A.1 and
A.3, 70 Python/OpenSSL-based comparisons, the 255th output block and
atomic rejection on Windows x64. Source-to-Lean refinement, timing
evidence, key-state erasure and benchmarks remain open.
[RFC 5869 Appendix A](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)
