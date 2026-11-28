# C# Pure deterministic ML-DSA-65

The SDK takes a 32-byte seed and emits a 1,952-byte public key and
3,309-byte signature. It signs in Pure deterministic mode with a
binary context of at most 255 bytes and accepts empty messages.
Verification checks widths before passing the signature to the
provider's decoder and verifier. The adapter preserves the caller's
seed and clears its temporary copy.
[FIPS 204](https://doi.org/10.6028/NIST.FIPS.204),
[Pinned ACVP projection](../../spec/acvp-fips204-sample.json)

The NuGet SDK package is `Abc.Cryptography.MlDsa65` 0.1.0.
It depends on the locked Bouncy Castle 2.7.0 archive.
[Provider lock and checks](../../../../providers/csharp/README.md)

```sh
python -B src/crypto/providers/csharp/check.py --profile ml-dsa-65
```

The isolated consumer checked four NIST ACVP results, including
verification of the published deterministic signature. It matched
16 OpenSSL bidirectional cases up to the 255-byte context boundary,
rejected five malformed hint encodings, and reproduced 12 deterministic
signatures byte for byte with OpenSSL 3.5.4. Set `ABC_MLDSA_OPENSSL` to an
OpenSSL 3.5.4 executable for the exact deterministic CLI checks.

The package follows the repository's research profile. Exact source
refinement, compiled leakage and comparative performance remain open.
