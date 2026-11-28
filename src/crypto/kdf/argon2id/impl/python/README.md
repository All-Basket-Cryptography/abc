# Argon2id v1.3 in Python

The per-profile entry point is [`abc_argon2id.py`](abc_argon2id.py). The Python API delegates the cryptographic primitive to the pinned cryptography wheel's OpenSSL provider.

Derive a tag from password and salt bytes with explicit passes, lanes, output length and caller memory budget. Optional secret and associated data are byte strings. The budget charges the RFC-rounded matrix allocation plus output bytes and excludes provider overhead.

Use the pinned [provider setup](../../../../providers/python/README.md), then run this command from the repository root.

```sh
python -B -m unittest discover -s src/crypto/kdf/argon2id/impl/python
```

The RFC test exercises secret and associated data, memory rounding, and the exact budget boundary.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [RFC 9106 §§ 3 and 5.3](https://www.rfc-editor.org/rfc/rfc9106.html)
