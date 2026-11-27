# AES-256

This portable Rust research primitive implements 14 AES rounds, a 256-bit
key schedule, and forward and inverse transformations of a 16-byte block.
The S-box uses field inversion and an affine map. Its polynomial squaring
spreads eight bits into a 16-bit word and reduces with two fixed folds.
The implementation has no secret-indexed lookup tables at source level. Timing and key erasure
must be assessed for each compiled target.
[FIPS 197, May 2023 update](https://csrc.nist.gov/pubs/fips/197/final)

Rust tests check AES-256 known answers, all 256 byte inversions and all
256 polynomial squares against multiplication. Lean checks the square and
forward/inverse byte substitution equations by kernel reduction on every
byte. Full Rust refinement of the S-box, schedule, or block operations
and hardware performance qualification remain open.
[NIST block cipher verification resources](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers)
