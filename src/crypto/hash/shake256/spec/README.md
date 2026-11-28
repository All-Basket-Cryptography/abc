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

The source replay uses pinned Charon to check the Rust constructor,
incremental absorption, finalizer, output reader and one-shot `xof`.
Lean proves that each output bit equals the FIPS 202 bit sponge for any
finite partition of the input and output. The proof also establishes that
the concatenated streaming bytes equal the one-shot result. The lowering
uses Rust's slice, iterator and integer-operation contracts.
[Streaming and one-shot proofs](../../keccak-p1600/spec/KeccakAbsorbSourceRefinement.lean) · [Replay and receipt](../../../../../tools/verification/keccak/README.md)

The Rust tests check known answers, a late-output vector reproduced with
CPython's `hashlib.shake_256(bytes(range(137))).digest(300)[268:]`, and
input and output partitions across multiple rate blocks. Qualification
of target performance and compiled code remains independent.
[NIST SHA-3 and SHAKE testing resources](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing)
