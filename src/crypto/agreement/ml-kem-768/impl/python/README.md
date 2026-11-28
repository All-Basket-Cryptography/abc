# ML-KEM-768 in Python

The per-profile entry point is [`abc_ml_kem_768.py`](abc_ml_kem_768.py). The Python API delegates the cryptographic primitive to the pinned cryptography wheel's OpenSSL provider.

Use a 64-byte d∥z seed, a 1184-byte encapsulation key and a 1088-byte ciphertext. Encapsulation uses fresh provider randomness. A correctly sized altered ciphertext produces a 32-byte implicit-rejection secret.

Use the pinned [provider setup](../../../../providers/python/README.md), then run this command from the repository root.

```sh
python -B -m unittest discover -s src/crypto/agreement/ml-kem-768/impl/python
```

The tests compare NIST ACVP public keys, both sides of encapsulation across providers, key canonicality and implicit rejection. The separately maintained JavaScript/Noble route provides the interoperation oracle.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
