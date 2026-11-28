# C11 AES-256 with AES-NI

Compile `abc_aes256_c.c` with a C11 compiler and include
`abc_aes256_c.h`. The x86-64 core uses the processor's AES round and
key expansion instructions. `abc_aes256_c_init` requires a 32-byte key,
checks CPUID and expands both directions. It reports unsupported on
machines without the AES instructions. Use each context only after
successful initialization. Encrypt and decrypt take exactly one
16-byte block and allow overlapping input and output. The buffers must
lie outside the context. Use `abc_aes256_c_clear` to overwrite the
stored schedule before releasing the context.
[FIPS 197, May 2023 update](https://csrc.nist.gov/pubs/fips/197/final)

The Windows x64 Clang 21.1.8 Release and UBSan trap builds passed two
NIST known answers and 512 independent encryption plus 512 independent
decryption comparisons against OpenSSL 3.5.4 through Node 24.12.0.
Tests exercise shifted overlap, destination canaries, rejected inputs
and clearing the stored schedule. AES-NI removes source-level
secret-indexed lookup tables. The existing Lean byte model covers
independent building blocks. Source refinement to the processor
instructions, target timing, memory lifetime and throughput
qualification remain open.
[NIST SP 800-38A, Appendix F.1.5](https://csrc.nist.gov/pubs/sp/800/38/a/final) · [Lean AES byte model](../../spec/Aes256Byte.lean)

```sh
python -B src/crypto/cipher/aes256/impl/c/check.py
python -B src/crypto/cipher/aes256/impl/c/check.py --ubsan
```
