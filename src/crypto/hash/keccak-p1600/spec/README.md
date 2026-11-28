# Keccak-p[1600,24] and 1088-bit-rate sponge model

The Lean model checks the 25 rotation offsets from the rho coordinate
recurrence, the pi destination table and its inverse, and the 24 iota
constants from the FIPS shift register. For arbitrary 1,600-bit input,
`permutation_bits` shows that all 24 word-oriented rounds produce the
same individual bits as the bit-oriented round definitions. The pi
scatter theorem gives the corresponding source for every destination.
[FIPS 202 §3.2](https://csrc.nist.gov/pubs/fips/202/final)

`packed_lane_byte` checks the byte position within a 64-bit lane.
`padding_writes_match` treats both supported domain bytes and includes the
135-byte tail in which the suffix and final padding bit share a byte.
`sponge_blocks_match` composes absorption, that padding step, and any
finite number of squeezed rate blocks for arbitrary input blocks and
tail bytes. The rate and capacity partition is reflected in the first
17 absorbed lanes and eight untouched capacity lanes before permutation.
[FIPS 202 §4 and §6](https://csrc.nist.gov/pubs/fips/202/final)

```sh
lean -DwarningAsError=true src/crypto/hash/keccak-p1600/spec/KeccakRound.lean
```

Lean 4.31.0 checks the theorems using kernel reduction and the standard
axioms `propext`, `Classical.choice` and `Quot.sound`. The theorem
interface uses typed rate blocks, a tail length below 136 and exact
word semantics. The Go and Python conformance tests cover their concrete
streaming buffers and partial reads. A source-to-model refinement for
the Go and Python buffers and compiled timing is still open.

Pinned Charon extracts the Rust Keccak permutation and the 136-byte block
absorption path. Lean checks the resulting round and absorb expressions
against the bit-oriented model over every input state and block. The
proof also composes those two source-linked operations with the rate and
padding models for SHA3-256 and SHAKE256.
[Rust source refinement](KeccakSourceRefinement.lean) · [Reproduction and receipt](../../../../../tools/verification/keccak/README.md)

The Rust wrapper replay checks the SHA3-256 byte digest, and the SHAKE256
finalizer through its first encoded rate block. Lean checks all domain
padding cases, including a tail of 135 bytes, and proves reads from the
finalized SHAKE256 state agree with FIPS for every finite read partition.
[Wrapper refinements](KeccakWrapperSourceRefinement.lean) · [Reader refinements](KeccakReaderSourceRefinement.lean)

The ECMAScript implementation reuses private permutation work arrays and
uses three linear parts for each chi row. Lean relates both neighbor
indices in each of those parts to the modulo-ten definition for every
32-bit limb. The reader model relates each bounded span to the corresponding
rate-block position, including the paused position at byte 136. For any
finite read partition, its output bytes and final absolute cursor agree
with a single read of the same size. The block theorem then composes
these reads with the FIPS bit sponge and proves that every returned bit
agrees with it for arbitrary finite read partitions. The JavaScript and
TypeScript conformance suite tests the concrete typed-array state and API.
[Reader model](KeccakReader.lean) · [Composed FIPS read theorem](KeccakSpongeRead.lean)

```sh
python -B src/lean/check.py keccak-reader
```
