# Portable C++17 SHA-256

`sha256.cpp` implements FIPS 180-4 directly using unsigned 32-bit words and
big-endian byte encoding. The C++17 API provides `Hasher::update`, a
non-consuming `Hasher::digest`, `reset`, and one-shot `hash`. Calls on one
context must be serialized. The context retains no caller buffers. Its
byte-length limit is `2^61 - 1`. Length and null-pointer rejection preserve
the stream and any output argument. Admissible nonempty updates require a
readable input extent outside the context object. The one-shot call accepts
overlap between the input and output arrays. [FIPS 180-4, August 2015](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

## Reproduction

Run from the repository root with Clang and a C++17 standard library. On
Windows, use the Visual Studio C++ toolchain and Windows SDK for Clang's MSVC
target. LLVM coverage and the undefined-behavior sanitizer require the
corresponding LLVM tools and runtime.

```text
python src/crypto/hash/sha256/impl/cpp/check.py
python src/crypto/hash/sha256/impl/cpp/check.py --coverage --ubsan
python src/crypto/hash/sha256/impl/cpp/check.py --benchmark
```

The check compiles the native core and links a separate consumer. On Windows
x64, Clang 21.1.8 at `-O2` passed four known-answer cases, 151 differential
one-shot comparisons against Python `hashlib` backed by OpenSSL 3.0.21, 155
oracle-checked prefix snapshots, and 2,728 two-chunk splits. Cases include
the empty message, one million `a` bytes, padding and block boundaries, and
seeded binary messages. The UBSan run also passed overlap, null, and length
rejection checks. LLVM measured 102 of 102 source lines, 53 of 53 source
regions, and 32 of 32 branch outcomes in `sha256.cpp`. [NIST `abc` worked example](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha256.pdf) · [CAVP byte vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) · [RFC 6234 § 8.5](https://www.rfc-editor.org/rfc/rfc6234.html#section-8.5)

| Input | SHA-256 |
| --- | --- |
| `sha256.cpp` | `15e46cbff8cd8ccd5663855958201e87359a4a72dd130699f3b32cd8cac1370c` |
| `sha256.hpp` | `3243c39b293d51a848d461273536d3df4126c0e4284e3df3555e047f25cc9bf0` |
| `tests.cpp` | `e018900ef593a93ffd3a11debbe290a5970650a23b7538c28d2087745375309e` |

The uninstrumented build measured a median of 363.24 MiB/s on one Windows
x64 host with Intel Family 6 Model 151. It hashed a fixed 1 MiB message for
four warm-up calls, followed by seven timed batches of 16 calls. Batch
throughput ranged from 352.39 to 368.15 MiB/s.

The next formal obligation is checked correspondence for C++ word
arithmetic, pointer ranges, and block access, followed by the streamed
counter, padding, and snapshot semantics. The existing Lean model supplies
the independent mathematical target. Source refinement, standalone package
qualification, and target binary and leakage evidence remain open.
[Lean SHA-256 specification](../../spec/Sha256Spec.lean)
