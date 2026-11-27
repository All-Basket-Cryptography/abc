# Portable C# HKDF-SHA-256

This research core implements extract, expand and derive in managed C#
using the portable HMAC and SHA-256 projects. Extract produces a 32-byte
PRK, and an empty salt uses the RFC default. Expand accepts a PRK of 32
bytes or longer, with output of 0–8160 bytes. Expand and derive reject
overlap between info and the output, before any output writes.
[RFC 5869 §§ 2.2–2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.2)

Run `python -B src/crypto/kdf/hkdf-sha256/impl/csharp/check.py` with .NET
SDK 10.0.404. The script accepts `--dotnet` for a separate installation,
builds a consumer offline, and compares against RFC vectors and .NET
HKDF. The Windows x64 run passed RFC 5869 cases A.1 and A.3, 70
comparison cases, the 255th output block and atomic rejection.
Source-to-Lean refinement, JIT timing evidence, benchmarks,
package distribution and key-state erasure remain open.
[RFC 5869 Appendix A](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)
