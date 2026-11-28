# C# SDK package conformance

The checker uses .NET SDK 10.0.404 and a separate build and NuGet package
cache per profile. It verifies the exact Bouncy Castle archive, packs
the requested SDK, and restores a separate consumer project against
a local-only feed with the single SDK package reference. It checks
the complete dependency closure and matches both consumer DLLs to the
packaged bytes. The provider archive stays outside Git.
[Locked Bouncy Castle release](https://www.nuget.org/packages/BouncyCastle.Cryptography/2.7.0),
[Provider source commit](https://github.com/bcgit/bc-csharp/tree/4007498b13582d90ee1eda5d9920c324428b98b3)

Use `--bc-nupkg` or `ABC_BC_NUGET` to provide the locked package for
an offline run. Without that option the checker retrieves the one
locked artifact from NuGet before creating the local feed. Select
OpenSSL 3.5+ libcrypto for the Ed25519 consumer with `--libcrypto`
or `ABC_OPENSSL_LIBRARY`. `--output` retains the tested SDK package
and the receipt with source, package and DLL fingerprints.

```sh
python -B src/crypto/providers/csharp/check.py --profile x25519 --bc-nupkg PATH_TO_BOUNCY_CASTLE_NUPKG
```

Each validation runs on one isolated SDK. The OpenSSL comparison
inputs and NIST projections are shared where possible. The resulting
receipts cover interoperability, negative input handling and package
consumption. Complete provider source refinement and compiled
side-channel evidence remain separate work.
