# Portable C# PBKDF2-HMAC-SHA-256

This research core derives bytes using the portable managed HMAC and
SHA-256 projects. `Derive` requires a positive `uint` iteration count and
a nonempty output span. The managed span limit fits the PBKDF2 block
index space. Long passwords are hashed once before the derivation.
Salt and output overlap is rejected before any write. Set caller-level
limits on iteration counts and output lengths to bound derivation work.
[RFC 8018 § 5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2)

Run `python -B src/crypto/kdf/pbkdf2-hmac-sha256/impl/csharp/check.py` with
.NET SDK 10.0.404. The script accepts `--dotnet` for a separate installation
and builds its consumer offline. The Windows x64 run passed two RFC 7914
vectors, 45 .NET PBKDF2 comparisons and atomic rejection. Source-to-Lean
refinement, JIT timing
evidence, benchmarks, package distribution and key-state erasure remain open.
[RFC 7914 § 11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)
