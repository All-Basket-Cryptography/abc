# SHA-512

The portable cores implement byte-aligned SHA-512 with a 128-byte
compression block, an 80-word schedule and a 16-byte big-endian bit length.
One-shot and arbitrary streaming updates return a 64-byte big-endian digest.
Before accepting an update, the context checks that the total encoded
bit length remains below `2^128`. The Rust core uses no heap or unsafe code.
[FIPS 180-4, §§ 4–6](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

Initialization and round constants are the low 64 bits of the floor of
the scaled square or cube root of each prime, as specified in FIPS 180-4.
The Lean length lemmas cover the mathematical admission condition, the
padded length, the one-to-two-block padding boundary and the conversion
from a two-word byte count to a 128-bit bit count. Lean proves that the
16-word schedule used by Go preserves the last 16 reference schedule words
at each expansion step. The portable Rust functional model matches the
separate FIPS model for every block, one-shot byte list and admitted finite
stream partition. It checks both padding branches and models rejection as
preservation of the stream view. The runner records the reviewed Rust
source, independently derives the constants and audits the Lean statements
and axioms. Formal translation of Rust semantics and the other languages'
source refinements remain open.
[Length lemmas](Sha512Length.lean) · [Schedule model](Sha512Ring.lean) · [FIPS model](Sha512Spec.lean) · [Compression theorem](Sha512Compression.lean) · [Stream theorems](Sha512Streaming.lean) · [Reproduction and receipt](../../../../../tools/verification/sha512/README.md)

The Rust tests check empty and `abc` known answers, failed updates, and
all split points against independent CPython `hashlib.sha512` digests for
the prefixes of `bytes((i*i + 17) % 256 for i in range(257))`. The portable
research implementation requires independent performance and security
qualification on the selected target.
[NIST Secure Hashing test resources](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing)

The Go, Java, and Python implementations each have independent oracle tests and
all-split checks around the padding and block boundaries.
[Go implementation](../impl/go) · [Java implementation](../impl/java) · [Python implementation](../impl/python)

The additional C, C++, C#, JavaScript, TypeScript, Kotlin and Swift
cores expose streaming snapshots and have independent provider suites.
Lean checks the C two-word counter and the split-word rotations, shifts and
modular carry model used by the JavaScript and TypeScript implementations.
[C counter](../impl/c/proof/Sha512LengthHalves.lean) · [Split-word model](Sha512SplitWord.lean)
