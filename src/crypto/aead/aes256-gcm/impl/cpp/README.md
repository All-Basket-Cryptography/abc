# C++17 AES-256-GCM with AES-NI

Compile `aes256_gcm.cpp` together with the C++17 AES-256 module.
`Gcm` accepts a 32-byte `Key`, uses a 12-byte `Nonce` and returns
a detached 16-byte `Tag`. AES rounds and key expansion require an
x86-64 processor with AES-NI. GHASH multiplies each block using 128
fixed arithmetic steps, and pads associated data and ciphertext
separately. Choose a distinct nonce for every seal under the same key.
[C++17 AES-256 module](../../../../cipher/aes256/impl/cpp/README.md) · [NIST SP 800-38D §§5–8](https://csrc.nist.gov/pubs/sp/800/38/d/final)

After `initialize`, use `seal` and `open` with an output length equal
to the payload length. Input and output may overlap, including shifted
overlap. The seal tag destination must be disjoint from the ciphertext
output. Empty buffers may be null. Use readable or writable buffers for
their declared lengths outside the context. The payload limit is
`(2^32 - 2) * 16` bytes and the associated data limit is
`floor((2^64 - 1) / 8)` bytes. Open checks the full tag before writing
plaintext. The destructor and `clear` overwrite the stored schedule
and hash subkey.

Windows x64 Clang 21.1.8 Release and UBSan trap builds passed two
NIST vectors, 272 independent bidirectional cases against OpenSSL
3.5.4 through Node 24.12.0, and 18 authentication rejections. They also
passed length bounds, shifted overlap, associated data aliasing and
preservation of rejected outputs.
[NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)

```sh
python -B src/crypto/aead/aes256-gcm/impl/c/check.py --language cpp
python -B src/crypto/aead/aes256-gcm/impl/c/check.py --language cpp --ubsan
```

The Lean model covers independent counter and tag-comparison
properties. Source refinement, timing and key-lifetime analysis on
the target, and hardware performance qualification remain open.
[Lean GCM bounds](../../spec/Aes256GcmBounds.lean)
