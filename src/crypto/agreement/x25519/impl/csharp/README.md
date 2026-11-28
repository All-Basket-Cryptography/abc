# C# X25519

The SDK consumes 32-byte raw inputs and returns an owned public key
or shared secret. It clears bit 255 of the peer encoding and reduces
the masked peer value modulo `2^255 - 19`. Low-order peers return
`null`. Invalid input lengths raise an argument error. The calling
protocol supplies fresh private bytes, authenticates the exchange
and binds its transcript when deriving session keys.
[RFC 7748 §§5–6](https://www.rfc-editor.org/rfc/rfc7748.html#section-5)

The NuGet SDK package is `Abc.Cryptography.X25519` 0.1.0.
It depends on the locked Bouncy Castle 2.7.0 archive.
[Provider lock and checks](../../../../providers/csharp/README.md)

```sh
python -B src/crypto/providers/csharp/check.py --profile x25519
```

The isolated consumer passed both RFC Alice/Bob directions and the
first and 1,000th RFC iteration results. It also matched 196 OpenSSL
cases including noncanonical encodings, preserved caller inputs and
rejected 14 low-order encodings or aliases.

The package follows the repository's research profile. Exact source
refinement, compiled leakage and comparative performance remain open.
