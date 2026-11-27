# AES-256

This portable Rust research primitive implements 14 AES rounds, a 256-bit
key schedule, and forward and inverse transformations of a 16-byte block.
The S-box uses field inversion and an affine map. The implementation has
no secret-indexed lookup tables at source level. Timing and key erasure
must be assessed for each compiled target.
[FIPS 197, May 2023 update](https://csrc.nist.gov/pubs/fips/197/final)

Rust tests check AES-256 known answers and all 256 byte inversions. Lean
checks the forward/inverse byte substitution equations by kernel reduction
on every byte. Full Rust refinement of the S-box, schedule, or block
operations remains open. The portable implementation does not yet have a
hardware-backed performance qualification.
[NIST block cipher verification resources](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers)
