# C# SHAKE256

The native C# profile exposes `HashData`, `Update`, `Reset` and `Finish`.
Finalization returns an independent reader at byte offset zero and
keeps the absorber available for more input. The reader can return new
bytes or fill caller-owned storage through `Read` and `ReadInto`.
The same-language Keccak-p[1600,24] core uses domain byte `0x1f`.
[FIPS 202 §6.2](https://csrc.nist.gov/pubs/fips/202/final) · [Shared core](../../../keccak-p1600/impl/csharp)

Use .NET SDK 10.0.404. Pass `--dotnet` or set `ABC_DOTNET` to select it.
The checker uses an isolated offline NuGet feed and a separate consumer.

```sh
python -B src/crypto/hash/keccak-p1600/impl/java/check.py --language csharp --algorithm shake256
```

The isolated consumer tests the NuGet package and its transitive
native Keccak core. It compares 11 one-shot vectors and 2,439 split
traces against Node 24.12.0/OpenSSL 3.5.4, including known-answer and
rate-boundary cases. Every split reads 409 bytes using multiple output
chunk sizes and independent readers. Use `--output` to retain the tested
artifacts and source digests.
[NIST example values](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values)

Lean checks the complete word-oriented permutation and block-oriented
sponge model. Exact C# source refinement and compiled-target
leakage and performance qualification remain open.
[Lean model](../../../keccak-p1600/spec)
