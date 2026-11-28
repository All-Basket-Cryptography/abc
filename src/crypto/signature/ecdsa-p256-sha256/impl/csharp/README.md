# C# deterministic ECDSA P-256 with SHA-256

The SDK accepts a 32-byte big-endian private scalar in the interval
`1..n-1`. Public-key derivation emits an uncompressed SEC 1 point.
Verification accepts exact compressed and uncompressed SEC 1
encodings and a 64-byte P1363 signature. Signing preserves the
deterministic RFC 6979 `s` value. Verification accepts both
representatives of `s`.
[RFC 6979 Appendix A.2.5](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5),
[P-256 domain parameters](https://csrc.nist.gov/pubs/sp/800/186/final)

The NuGet SDK package is `Abc.Cryptography.EcdsaP256Sha256` 0.1.0.
It depends on the locked Bouncy Castle 2.7.0 archive.
[Provider lock and checks](../../../../providers/csharp/README.md)

```sh
python -B src/crypto/providers/csharp/check.py --profile ecdsa-p256-sha256
```

The isolated consumer reproduced two RFC signatures and the RFC public
key, repeated 50 signatures deterministically, and checked 50 public keys
and both signature directions against OpenSSL. It checked both accepted
SEC 1 forms, both S representatives, the private scalar endpoints, and
malformed scalars, points and signatures.

The SDK supplies its own RFC 6979 HMAC nonce state. When the signing
provider requests another candidate, the SDK applies the rejection
transition from step h.3 before generating it. The consumer checked
the second nonce against an independent HMAC transcript and forced
an initial zero-`s` signature at the provider boundary. It observed
one retry and verified the output produced by the next nonce.
[RFC 6979 §3.2](https://www.rfc-editor.org/rfc/rfc6979.html#section-3.2)

The package follows the repository's research profile. Exact source
refinement, compiled leakage and comparative performance remain open.
