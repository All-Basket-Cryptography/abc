# Portable Java 17 HMAC-SHA-256

This research core implements full-tag HMAC in Java using the independent
Java SHA-256 core. Supply a key array and append any number of message
slices. The key is copied into hash state and the input slices are consumed
during each call. `digest()` returns a new, non-consuming 32-byte snapshot.
Invalid array ranges or a message beyond the SHA-256 length bound minus 64
bytes preserve the stream state. Serialize access to individual contexts.
[RFC 2104 § 2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2)

Run `python -B src/crypto/mac/hmac-sha256/impl/java/check.py` with JDK 17.
Use `--jdk` for a separate installation. The script compiles a clean
consumer against distinct HMAC and SHA-256 JARs. JDK 17.0.12 passed three
RFC 4231 vectors and 153 JCA HMAC comparisons on Windows x64, including key
buffer ownership, digest isolation and atomic range rejection.
Source-to-Lean refinement, JVM timing evidence, benchmarks, package
distribution and key-state erasure remain open.
[RFC 4231 § 4](https://www.rfc-editor.org/rfc/rfc4231.html#section-4)
