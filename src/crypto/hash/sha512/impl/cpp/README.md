# Portable C++ SHA-512

The independent C++17 implementation provides streaming SHA-512 under
`abc::native_sha512`. Compile `sha512.cpp` and link the object with a
consumer that includes `sha512.hpp`. `Hasher::digest` snapshots an open
stream and `Hasher::reset` starts a new message. A context holds fixed
arrays and the byte count, so hashing needs no heap allocation. One-shot
`hash` writes the destination after consuming input, which permits
overlap.

The implementation uses the 80-step FIPS compressor, explicit big-endian
words and two 64-bit byte-count limbs. It admits messages of at most
`2^125 - 1` bytes. Invalid input and counter overflow preserve the
context. The C++ compiler checks synthetic carry and exact-limit cases at
compile time. The repository provides
[mathematical SHA-512 length lemmas](../../spec/Sha512Length.lean) and a
[model of the two-limb carry rule](../c/proof/Sha512LengthHalves.lean).
End-to-end C++ source and compiled-code refinement remain open.
[FIPS 180-4 §§4.2.3, 5.1.2, 5.2.2, 5.3.5, and 6.4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

The checker compiles the core independently and links a consumer. On
Windows x64, Clang 21.1.8 passed four known answers, 152 OpenSSL
comparisons through CPython, 156 prefix snapshots and 3,166 split checks.
The same cases passed with UndefinedBehaviorSanitizer.
[NIST SHA-512 examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf)

```sh
python -B src/crypto/hash/sha512/impl/cpp/check.py
python -B src/crypto/hash/sha512/impl/cpp/check.py --ubsan
python -B src/crypto/hash/sha512/impl/cpp/check.py --benchmark
```

Use a Visual Studio developer environment on Windows. The local release
benchmark on an Intel Core i7-12700K measured about 572 MiB/s for 1 MiB
messages with this core and about 956 MiB/s with OpenSSL through CPython.
The comparison is specific to this host, compiler and interfaces.
