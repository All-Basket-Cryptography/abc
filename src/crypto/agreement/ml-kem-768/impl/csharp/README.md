# C# ML-KEM-768

The SDK accepts a 64-byte private seed `d || z` and returns a
1,184-byte public key. Encapsulation validates the public coefficients
before producing a 1,088-byte ciphertext and 32-byte secret with
provider-generated randomness. Decapsulation checks ciphertext width.
Invalid content of the correct width returns the implicit-rejection
secret. The adapter clears its temporary seed copy.
[FIPS 203](https://doi.org/10.6028/NIST.FIPS.203),
[Pinned ACVP projection](../../spec/acvp.json)

The NuGet SDK package is `Abc.Cryptography.MlKem768` 0.1.0.
It depends on the locked Bouncy Castle 2.7.0 archive.
[Provider lock and checks](../../../../providers/csharp/README.md)

```sh
python -B src/crypto/providers/csharp/check.py --profile ml-kem-768
```

The isolated consumer covered two NIST public-key derivations and the
NIST malformed public-key fixture, 12 OpenSSL bidirectional exchanges,
12 independently recomputed SHAKE256 implicit-rejection results, and
four random roundtrips. It rejected malformed lengths and either
coefficient position set to the modulus.

The package follows the repository's research profile. Exact source
refinement, compiled leakage and comparative performance remain open.
