# TypeScript Keccak-p[1600,24]

The byte sponge and each of the 24 permutation rounds use two
unsigned 32-bit words per lane. The lane order is `x + 5*y`.
The sponge uses a 136-byte rate. A finalization with domain byte
`0x06` or `0x1f` returns an independently owned reader.
[FIPS 202 §§3 and 5](https://csrc.nist.gov/pubs/fips/202/final)

```sh
node --test src/crypto/hash/keccak-p1600/impl/typescript/keccak.test.mts
```

The test checks all 25 lanes of the XKCP zero-state permutation. The
shared Lean model checks permutation and sponge equivalence to their
bit models. Source extraction and runtime leakage qualification remain
open. [XKCP intermediate values](https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt) · [Lean model](../../spec/KeccakRound.lean)
