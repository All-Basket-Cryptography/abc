# Ed25519 in Python

The per-profile entry point is [`abc_ed25519.py`](abc_ed25519.py). The Python API delegates the cryptographic primitive to the pinned cryptography wheel's OpenSSL provider.

Derive, sign or verify Pure Ed25519 with a 32-byte seed, 32-byte encoded public key and 64-byte signature. Verification rejects noncanonical and small-order A/R, and out-of-range S.

Use the pinned [provider setup](../../../../providers/python/README.md), then run this command from the repository root.

```sh
python -B -m unittest discover -s src/crypto/signature/ed25519/impl/python
```

The RFC test checks exact signatures and rejects malformed encodings and wrong messages.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [RFC 8032 §§ 5.1 and 7.1](https://www.rfc-editor.org/rfc/rfc8032.html)
