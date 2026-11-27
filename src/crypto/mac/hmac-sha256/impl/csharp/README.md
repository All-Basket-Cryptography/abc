# Portable C# HMAC-SHA-256

This research core implements full-tag HMAC in managed C# using the portable
managed SHA-256 project. Provide a key span, append message spans with
`Update`, and write a non-consuming 32-byte tag snapshot with `Digest`.
`Authenticate` reads both inputs before writing the tag. The key and message
spans are borrowed for each call. A short destination preserves the output
and a message beyond the SHA-256 length bound minus 64 bytes preserves the
context. Serialize access to individual contexts.
[RFC 2104 § 2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2)

Run `python -B src/crypto/mac/hmac-sha256/impl/csharp/check.py` with .NET
SDK 10.0.404. The script accepts `--dotnet` for a separate installation and
builds its consumer offline. The Windows x64 run passed three RFC 4231
vectors and 153 .NET HMAC comparisons covering key and block boundaries,
prefix snapshots, key buffer ownership and short destinations.
Source-to-Lean refinement, JIT timing evidence, benchmarks, package
distribution and key-state erasure remain open.
[RFC 4231 § 4](https://www.rfc-editor.org/rfc/rfc4231.html#section-4)
