# C# scrypt

The managed .NET SDK accepts password and salt byte spans, cost `N`,
block size `r`, lane count `p`, and output length in bytes. Its
C# Salsa20/8, BlockMix, and ROMix use the independent C#
PBKDF2-HMAC-SHA-256 core for both derivation steps. The caller owns the
returned array.
[RFC 7914 §§2–6](https://www.rfc-editor.org/rfc/rfc7914.html#section-2)

```csharp
using Abc.Cryptography;

long budget = (long)Scrypt.WorkspaceSize(cost, blockSize, parallel) + keyBytes;
byte[] key = Scrypt.Derive(password, salt, cost, blockSize, parallel, keyBytes, budget);
```

`WorkspaceSize` counts the primary buffers as
`128*r*(N + p + 2) + 128` bytes. ROMix reuses one history table for
all lanes and alternates between two BlockMix buffers. `Derive` checks
the workspace and output against the caller's budget before allocation.
The workspace and output are each capped at `int.MaxValue - 64`.
Object headers, PBKDF2 temporary state, and available managed heap
capacity are outside the budget calculation.

The implementation leaves caller inputs intact and invokes
`CryptographicOperations.ZeroMemory` on its workspace after use.
ROMix uses data-dependent table reads.
[RFC 7914 §14](https://www.rfc-editor.org/rfc/rfc7914.html#section-14),
[.NET ZeroMemory](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptographicoperations.zeromemory)

```sh
python -B src/crypto/kdf/scrypt/impl/csharp/check.py
lean -DwarningAsError=true src/crypto/kdf/scrypt/impl/csharp/ScryptCSharpBounds.lean
```

The checker packs four managed NuGet packages and restores a separate
consumer referencing only `Abc.Cryptography.Scrypt` from the local
feed. The .NET 10.0.404 SDK and .NET 10.0.15 runtime passed three RFC
known answers and 144 additional CPython 3.13.14/OpenSSL 3.0.21 cases.
All 147 cases accepted the exact budget and rejected one byte less.
The consumer also rejected 11 malformed parameter sets.
Use `--output` to retain the tested packages and receipt.
[RFC 7914 §12](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)

The Lean models check checked-product and budget arithmetic, lane
offset and table bounds, and the BlockMix scatter and Integerify
index formulas. Full source refinement, compiled leakage evidence,
and comparative performance measurements remain open.
[Lean C# bounds](ScryptCSharpBounds.lean),
[Shared Lean model](../../spec/ScryptBounds.lean)
