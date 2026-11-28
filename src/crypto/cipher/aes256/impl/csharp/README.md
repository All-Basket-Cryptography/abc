# AES-256 C# SDK

The `Abc.Cryptography.Aes256` NuGet package targets .NET 10 and uses
`System.Security.Cryptography.Aes` for its AES rounds and key schedule.
The runtime selects the platform provider. The C# SDK validates the
32-byte key, retains one transform for each direction and exposes a
single 16-byte block per call with no padding. Use the authenticated
AES-256-GCM package for message encryption.
[FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) · [.NET platform cryptography](https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography)

```csharp
using Abc.Cryptography;

using var cipher = new Aes256Cipher(key);
cipher.EncryptBlock(input, output);
```

Input and output may overlap, including a shifted overlap. Serialize
operations on each instance and dispose it when finished. The SDK
clears its temporary block buffers and disposes both provider handles.
Invalid block lengths leave the output unchanged.

The verifier packs the SDK and restores a separate consumer from a
local-only NuGet feed using SDK 10.0.404. Windows x64 .NET 10.0.15
passed two NIST known answers, 512 independent OpenSSL 3.5.4
encryption comparisons and 512 independent decryption comparisons.
Tests also cover shifted overlap, output canaries and rejection after
disposal. The Lean byte model covers AES building blocks. Provider
source refinement, compiled-target timing and complete key-lifetime
assurance remain open.
[NIST SP 800-38A, Appendix F.1.5](https://csrc.nist.gov/pubs/sp/800/38/a/final) · [Lean AES byte model](../../spec/Aes256Byte.lean)

On an Intel Core i7-12700K, the same-process medians over seven
100,000-operation batches were 79.5 ns encrypt and 84.5 ns decrypt for
the SDK, and 53.8 ns encrypt and 58.2 ns decrypt for the direct .NET
provider transforms. The measurements exclude setup, reuse key
schedules and recorded zero managed bytes allocated per operation.

```sh
python -B src/crypto/cipher/aes256/impl/csharp/check.py aes256 --output .abc/nuget
python -B src/crypto/cipher/aes256/impl/csharp/check.py aes256 --benchmark
```
