# ML-KEM-768 for C++17

Compile `ml_kem_768.cpp` with the OpenSSL development headers
and link libcrypto. The C++ adapter uses the OpenSSL default provider
for cryptographic computation.

The API uses a 1,184-byte encapsulation key, 2,400-byte expanded
decapsulation key, 1,088-byte ciphertext and 32-byte shared
secret. Key generation and encapsulation use provider randomness.
Decapsulation returns the provider’s implicit-rejection secret for
correctly sized ciphertexts that fail the reencryption check.
The adapter stages successful outputs and clears its temporary
copies of private keys and shared secrets.
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) · [OpenSSL ML-KEM](https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/)

The verifier builds a production-shaped library and tests a random
encapsulation round trip. A separate `ABC_MLKEM768_TESTING` build
admits deterministic fixture inputs and matches eight NIST ACVP
cases, including an implicit-rejection secret and untouched outputs
when malformed keys are rejected. The production-shaped binary is
checked for absence of the deterministic test entry points.
[Pinned NIST vectors](../../spec/acvp.json)

Source refinement of provider operations, compiled timing, complete
key-material erasure and production qualification remain open.

Windows x64 Clang 21.1.8 Release and UBSan adapter checks passed
against Git for Windows OpenSSL 3.5.4, SHA-256
`9325e8486c61b3227abeacf635279a10b828a3b39bc1124a6b5159ae00174181`.
Set `ABC_OPENSSL_INCLUDE` to the matching development include
directory. An explicitly fingerprinted OpenSSL 3.x build can be
selected by passing `--openssl-dll` and `--dll-sha256`.

```sh
python -B src/crypto/agreement/ml-kem-768/impl/cpp/check.py kem
python -B src/crypto/agreement/ml-kem-768/impl/cpp/check.py kem --ubsan
```
