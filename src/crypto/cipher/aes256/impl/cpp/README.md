# C++17 AES-256 with AES-NI

Compile `aes256.cpp` as C++17 and include `aes256.hpp`. The x86-64 core
uses the processor's AES round and key expansion instructions.
`Cipher::initialize` checks CPUID, accepts a `Key` of 32 bytes and
expands both directions. It reports unsupported on machines without
the AES instructions. `encrypt` and `decrypt` operate on one
16-byte `Block`, which can be passed as both input and output.
`clear` and the destructor overwrite the stored key schedule, and a
cleared instance requires another successful initialization.
[FIPS 197, May 2023 update](https://csrc.nist.gov/pubs/fips/197/final)

The Windows x64 Clang 21.1.8 Release and UBSan trap builds passed two
NIST known answers and 512 independent encryption plus 512 independent
decryption comparisons against OpenSSL 3.5.4 through Node 24.12.0.
They also check in-place operation and preserved output at invalid
context states. The core uses no source-level secret-indexed lookup
tables. The existing Lean byte model covers independent building
blocks. Source refinement to the processor instructions, target
timing, memory lifetime and throughput qualification remain open.
[NIST SP 800-38A, Appendix F.1.5](https://csrc.nist.gov/pubs/sp/800/38/a/final) · [Lean AES byte model](../../spec/Aes256Byte.lean)

```sh
python -B src/crypto/cipher/aes256/impl/c/check.py --language cpp
python -B src/crypto/cipher/aes256/impl/c/check.py --language cpp --ubsan
```
