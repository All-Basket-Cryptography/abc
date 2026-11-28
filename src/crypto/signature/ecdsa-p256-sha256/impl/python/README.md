# Deterministic ECDSA P-256 with SHA-256 in Python

The per-profile entry point is [`abc_ecdsa_p256.py`](abc_ecdsa_p256.py). The Python API delegates the cryptographic primitive to the pinned cryptography wheel's OpenSSL provider.

Use a 32-byte private scalar, SEC 1 compressed or uncompressed public keys for verification, and 64-byte IEEE P1363 signatures. The SDK returns the uncompressed key and preserves the original S value in deterministic output.

Use the pinned [provider setup](../../../../providers/python/README.md), then run this command from the repository root.

```sh
python -B -m unittest discover -s src/crypto/signature/ecdsa-p256-sha256/impl/python
```

The RFC tests check both SHA-256 signatures, including a high-S output, and public-key encoding.

The pinned OpenSSL signing path was exercised by the standard vectors. Complete RFC 6979 retries when the signature scalar is zero require separate provider evidence.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [RFC 6979 § 3.2 and Appendix A.2.5](https://www.rfc-editor.org/rfc/rfc6979.html)
