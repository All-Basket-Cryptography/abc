# SHA-512

The portable Rust core implements byte-aligned SHA-512 with a 128-byte
compression block, an 80-word schedule and a 16-byte big-endian bit length.
One-shot and arbitrary streaming updates return a 64-byte big-endian digest.
Before accepting an update, the context checks that the total encoded
bit length remains below `2^128`. The core uses no heap or unsafe code.
[FIPS 180-4, §§ 4–6](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

Initialization and round constants are the low 64 bits of the floor of
the scaled square or cube root of each prime, as specified in FIPS 180-4.
The checked Lean length lemmas cover the mathematical admission condition,
the padded length, and the one-to-two-block padding boundary. Full
implementation refinement of the word schedule, rounds and streaming state
is still open.

The native tests check empty and `abc` known answers, failed updates, and
all split points against independent CPython `hashlib.sha512` digests for
the prefixes of `bytes((i*i + 17) % 256 for i in range(257))`. The portable
research implementation requires independent performance and security
qualification on the selected target.
[NIST Secure Hashing test resources](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing)
