# Portable Java 17 PBKDF2-HMAC-SHA-256

This research core derives bytes using the independent Java HMAC and
SHA-256 implementations. Provide password and salt as byte arrays. The
iteration count is a long in `1..2^32-1` and the positive output length
fits a Java array. Long passwords are hashed once before the PRF loop.
The caller sets work and allocation limits on untrusted iteration counts
and lengths. The method returns a fresh output array.
[RFC 8018 § 5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2)

Run `python -B src/crypto/kdf/pbkdf2-hmac-sha256/impl/java/check.py` with
JDK 17. Use `--jdk` for a separate installation. The script compiles an
independent consumer against three separate JARs. JDK 17.0.12 passed two
RFC 7914 vectors, 45 JCA HMAC-based comparisons and invalid length checks
on Windows x64. Source-to-Lean
refinement, JVM timing evidence, benchmarks, package distribution and
key-state erasure remain open.
[RFC 7914 § 11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)
