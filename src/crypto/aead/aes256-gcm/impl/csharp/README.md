# AES-256-GCM C# SDK

The `Abc.Cryptography.Aes256Gcm` NuGet package targets .NET 10 and
uses `System.Security.Cryptography.AesGcm` for authenticated
encryption. The SDK fixes the key at 32 bytes, nonce at 12 bytes and
detached tag at 16 bytes. The runtime selects the platform provider.
Use a distinct nonce for each seal under the same key.
[NIST SP 800-38D §§5–8](https://csrc.nist.gov/pubs/sp/800/38/d/final) · [.NET platform cryptography](https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography)

```csharp
using Abc.Cryptography;

using var cipher = new Aes256GcmCipher(key);
cipher.Seal(nonce, associatedData, plaintext, ciphertext, tag);
bool authenticated = cipher.Open(nonce, associatedData, ciphertext, tag, recovered);
```

`Open` writes to the caller's plaintext only after the provider
authenticates the input. It returns `false` on an authentication
mismatch and preserves the destination. Payload input and output
must have equal lengths and may overlap. The seal tag output must
be disjoint from the ciphertext output. The SDK stages provider
output in a stack or pooled buffer and wipes its used region after
each operation. Check `IsSupported` on the target and serialize
operations on an instance. Dispose the instance when finished.
[.NET AesGcm.Decrypt](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm.decrypt?view=net-10.0)

The verifier packs the SDK and restores a separate consumer from a
local-only NuGet feed using SDK 10.0.404. Windows x64 .NET 10.0.15
passed two NIST known answers, 272 bidirectional OpenSSL 3.5.4
comparisons and 89 authentication rejection checks across both buffer
paths. Tests also cover shifted overlap, associated-data aliasing and
output boundaries. The Lean model covers GCM counter bounds and
tag-comparison equality. Provider source refinement, compiled-target
timing and complete key-lifetime assurance remain open.
[NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf) · [Lean GCM bounds](../../spec/Aes256GcmBounds.lean)

Same-process timings on an Intel Core i7-12700K used 32 bytes of
associated data and reused each key. The medians of seven batches are
shown below. All warmed paths recorded zero managed bytes allocated per
operation. The seal measurements include generating unique nonces.

| Payload | SDK seal | Direct .NET seal | SDK open | Direct .NET open |
| --- | ---: | ---: | ---: | ---: |
| 64 bytes | 195 ns | 158 ns | 152 ns | 139 ns |
| 4 KiB | 582 ns | 612 ns | 571 ns | 492 ns |

```sh
python -B src/crypto/cipher/aes256/impl/csharp/check.py aes256-gcm --output .abc/nuget
python -B src/crypto/cipher/aes256/impl/csharp/check.py aes256-gcm --benchmark
```
