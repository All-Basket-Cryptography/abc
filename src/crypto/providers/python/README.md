# Python crypto provider

The recorded target is CPython 3.13 on Windows x64. Install the wheel set with hash verification into the active virtual environment, from the repository root.

```sh
python -m pip install --only-binary=:all: --require-hashes -r src/crypto/providers/python/requirements-windows-x64.txt
```

The lock lists cryptography 50.0.2 and its dependency wheels. The qualified wheel reports OpenSSL 4.0.3. The Pure ML-DSA deterministic signer additionally accepts an absolute path to an OpenSSL 3.5+ libcrypto. The tested Windows DLL is Git for Windows OpenSSL 3.5.4, SHA-256 `9325e8486c61b3227abeacf635279a10b828a3b39bc1124a6b5159ae00174181`. Set `ABC_OPENSSL_LIBRARY` or construct the signer with that trusted path. Managed byte strings remain subject to Python runtime object lifetime.

Deterministic ECDSA signing uses the shared ABC C RFC 6979 engine. Set `ABC_ECDSA_P256_LIBRARY` to the absolute path of its built library or supply a `DeterministicSigner` instance. [Build and qualification instructions](../../signature/ecdsa-p256-sha256/impl/python/README.md)

The two post-quantum conformance suites also need the [ECMAScript oracle](../ecmascript/README.md). [cryptography 50.0.2](https://pypi.org/project/cryptography/50.0.2/) · [OpenSSL ML-DSA](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)
