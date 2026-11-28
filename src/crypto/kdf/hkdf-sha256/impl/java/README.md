# Portable Java 17 HKDF-SHA-256

This research core implements extract, expand and derive using the
independent Java HMAC and SHA-256 cores. Extract returns a fresh 32-byte
PRK and an omitted salt uses the RFC default. Expand requires a PRK of
32 bytes or longer and returns a fresh array of 0–8160 bytes. Provide an
empty array for empty info.
[RFC 5869 §§ 2.2–2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.2)

Run `python -B src/crypto/kdf/hkdf-sha256/impl/java/check.py` with JDK 17.
Use `--jdk` for a separate installation. The script compiles a clean
consumer against separate SHA-256, HMAC and HKDF JARs. JDK 17.0.12 passed
RFC 5869 cases A.1 and A.3, 70 comparisons using JCA HMAC, the 255th
output block and invalid length checks on Windows x64. Source-to-Lean
refinement, JVM timing evidence, benchmarks, package distribution and
key-state erasure remain open.
[RFC 5869 Appendix A](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)
