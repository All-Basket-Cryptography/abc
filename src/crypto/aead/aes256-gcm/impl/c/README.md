# C11 AES-256-GCM with AES-NI

Compile `abc_aes256_gcm_c.c` together with the C11 AES-256 module.
The profile uses a 32-byte key, a 12-byte nonce and a detached 16-byte
tag. The AES round and key schedule instructions require an x86-64
processor with AES-NI. GHASH uses a fixed 128 steps per block with
register arithmetic, and a separate padding boundary for associated
data and ciphertext. Each seal under a key requires a distinct nonce.
[C11 AES-256 module](../../../../cipher/aes256/impl/c/README.md) · [NIST SP 800-38D §§5–8](https://csrc.nist.gov/pubs/sp/800/38/d/final)

Initialize the context with `abc_aes256_gcm_c_init` and use it after
successful initialization. Seal and open require an output length
equal to the payload length. Ciphertext and plaintext may overlap,
including a shifted overlap. The seal tag destination must be disjoint
from its ciphertext output. Empty data buffers may be null. Use
readable or writable buffers for their declared lengths outside the
context. Payloads are bounded by `(2^32 - 2) * 16` bytes and associated
data is bounded by `floor((2^64 - 1) / 8)` bytes. Open checks the full
tag before writing plaintext. `abc_aes256_gcm_c_clear` overwrites the
stored schedule and hash subkey.

Windows x64 Clang 21.1.8 Release and UBSan trap builds passed two
NIST vectors, 272 independent bidirectional cases against OpenSSL
3.5.4 through Node 24.12.0, and 18 authentication rejections. They also
passed length bounds, shifted overlap, associated data aliasing and
preservation of rejected outputs.
[NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)

```sh
python -B src/crypto/aead/aes256-gcm/impl/c/check.py
python -B src/crypto/aead/aes256-gcm/impl/c/check.py --ubsan
```

The Lean model covers independent counter and tag-comparison
properties. Source refinement, timing and key-lifetime analysis on
the target, and hardware performance qualification remain open.
[Lean GCM bounds](../../spec/Aes256GcmBounds.lean)
