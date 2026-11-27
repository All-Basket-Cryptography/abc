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
those buffers, the permutation loops and compiled timing is still open.
