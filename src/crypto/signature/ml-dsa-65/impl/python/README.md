# Pure deterministic ML-DSA-65 in Python

The per-profile entry point is [`abc_ml_dsa_65.py`](abc_ml_dsa_65.py). The Python API uses cryptography for key derivation and verification and an explicitly selected OpenSSL 3.5+ libcrypto for deterministic signing. Set `ABC_OPENSSL_LIBRARY` to its absolute path or pass a `DeterministicSigner` instance.

Use a 32-byte seed, a 1952-byte verification key and a 3309-byte signature. The raw context is optional and admits up to 255 bytes. Signing uses the deterministic FIPS 204 mode.

Use the pinned [provider setup](../../../../providers/python/README.md), then run this command from the repository root.

```sh
python -B -m unittest discover -s src/crypto/signature/ml-dsa-65/impl/python
```

The tests check NIST ACVP key generation and signature verdicts and deterministic results across contexts. The separately maintained JavaScript/Noble route provides the interoperation oracle.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
