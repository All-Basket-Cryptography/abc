# SHAKE256

FIPS 202 defines SHAKE256 over Keccak-p[1600, 24], using a 136-byte rate
for byte-aligned messages. This API absorbs one or more chunks, applies
the SHAKE domain suffix on finalization, and returns a reader for arbitrary
byte output. An empty read leaves the reader unchanged. The current
crate allocates no heap storage. [FIPS 202 §§ 3–6](https://csrc.nist.gov/pubs/fips/202/final)

SHAKE256 and SHA3-256 share the Keccak permutation. SHAKE256 uses suffix
`0x1f` and a separate consuming finalization with a streaming reader.
The SHAKE padding combines the suffix and final bit into `0x9f` when
only one rate byte remains.

Lean checks that the padding fills one rate block, the boundary suffix,
and the finite-stream equation for split reads. Full Rust-to-Lean
refinement of the permutation and buffer transitions remains open.

The Rust tests check known answers, a late-output vector reproduced with
CPython's `hashlib.shake_256(bytes(range(137))).digest(300)[268:]`, and
input and output partitions across multiple rate blocks. Qualification
of target performance and compiled code remains independent.
[NIST SHA-3 and SHAKE testing resources](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing)
