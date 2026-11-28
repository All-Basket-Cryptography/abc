# C# strict Ed25519

The SDK derives a 32-byte public key and signs the supplied bytes
with a 32-byte seed. The 64-byte signature uses pure Ed25519.
Bouncy Castle supplies public-key derivation, signing and point
admission for both `A` and `R`. Verification uses the uncofactored
OpenSSL equation. Set `ABC_OPENSSL_LIBRARY` to the absolute path of an
OpenSSL 3.5 or newer libcrypto for verification.
[OpenSSL Ed25519](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ED25519/)
[RFC 8032 §§5.1 and 7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1)

The NuGet SDK package is `Abc.Cryptography.Ed25519` 0.1.0.
It depends on the locked Bouncy Castle 2.7.0 archive.
[Provider lock and checks](../../../../providers/csharp/README.md)

```sh
python -B src/crypto/providers/csharp/check.py --profile ed25519
```

The isolated consumer matched 99 independent Node/OpenSSL cases,
including three RFC 8032 vectors, with the local OpenSSL 3.5.4 runtime.
It rejected 12 malformed or small-order points in both fields, two
synthetic identity-equation cases, and malformed scalar and length
boundaries. The receipt identifies the loaded libcrypto by SHA-256.

The package follows the repository's research profile. Exact source
refinement, compiled leakage and comparative performance remain open.
