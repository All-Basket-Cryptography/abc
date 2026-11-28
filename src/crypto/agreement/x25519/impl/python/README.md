# X25519 in Python

The per-profile entry point is [`abc_x25519.py`](abc_x25519.py). The Python API delegates the cryptographic primitive to the pinned cryptography wheel's OpenSSL provider.

Derive a public key or shared secret from 32-byte inputs. The peer coordinate is masked and reduced modulo 2²⁵⁵−19. Low-order input yields a failed exchange. Bind the key exchange to the calling protocol.

Use the pinned [provider setup](../../../../providers/python/README.md), then run this command from the repository root.

```sh
python -B -m unittest discover -s src/crypto/agreement/x25519/impl/python
```

The RFC test checks public keys, agreement, coordinate aliases and low-order rejection.

Provider source refinement, compiled-code leakage and deployment targets remain outside the checked evidence. [RFC 7748 §§ 5 and 6.1](https://www.rfc-editor.org/rfc/rfc7748.html)
