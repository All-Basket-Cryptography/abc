# Poly1305 in C#

`Abc.Cryptography.Poly1305` exposes a 32-byte-key streaming `Poly1305Mac`
and the one-shot `Poly1305Mac.Authenticate`. The 16-byte tag closes the
streaming instance, and further calls throw. Each message requires a
fresh one-time key. Each instance is owned by one caller.
[RFC 8439 §§2.5 and 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5)

The offline NuGet consumer tests eight RFC answers at every split, 512
independent expanded-polynomial cases, 32 direct OpenSSL EVP-MAC cases,
tag bounds, and rejection after finalization. Select .NET SDK 10.0.404
and set `ABC_OPENSSL` when OpenSSL is outside the path.

```sh
python -B src/crypto/cipher/chacha20/impl/csharp/check.py poly1305
```

The Lean reduction model proves mathematical reduction and recurrence
properties. Complete correspondence with C# limbs and JIT timing remain
open. Keyed state arrays are cleared when the instance is disposed.
[Lean reduction model](../../spec/Poly1305Reduction.lean)
