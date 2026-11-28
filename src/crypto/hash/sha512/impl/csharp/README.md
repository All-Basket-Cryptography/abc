# Portable C# SHA-512

The managed `Abc.Cryptography.Sha512` package provides a streaming
`Sha512Hasher`. `Update` adds a byte span, `Digest` writes a
non-destructive snapshot and `Reset` starts a fresh message. The one-shot
`Hash` method permits overlap and writes exactly 64 bytes into a sufficiently
large destination. Caller input storage may be reused after successful
updates. One-shot hashing keeps its working state on the stack. Serialize
calls on each stream.

The compressor uses C# unsigned 64-bit words and explicit wrapping
arithmetic for the FIPS 180-4 SHA-512 schedule and rounds. The
`UInt128` byte counter admits inputs up to `2^125 - 1` bytes and
rejects overflow before changing the stream. The repository's
[mathematical length lemmas](../../spec/Sha512Length.lean) cover the
guard, padding and encoding. End-to-end C# and CLR refinement remain
open.
[FIPS 180-4 §§4.2.3, 5.1.2, 5.2.2, 5.3.5, and 6.4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

The checker packs the core and tests a separate consumer restored entirely
from an offline NuGet feed. On Windows x64, .NET SDK 10.0.404 and runtime
10.0.15 passed four known answers, 152 comparisons against
`System.Security.Cryptography.SHA512`, 156 prefix snapshots and 3,539
split checks. It also exercises caller ownership and the 128-bit
counter using synthetic state.
[NIST SHA-512 examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf)

```sh
python -B src/crypto/hash/sha512/impl/csharp/check.py
python -B src/crypto/hash/sha512/impl/csharp/check.py --benchmark
```

Select the pinned SDK executable with `--dotnet` or `ABC_DOTNET` when
it is outside PATH. On an Intel Core i7-12700K the local Release
benchmark measured about 464 MiB/s for 1 MiB messages with the
portable implementation and about 712 MiB/s with the platform SHA-512.
The comparison is specific to this host and runtime.
