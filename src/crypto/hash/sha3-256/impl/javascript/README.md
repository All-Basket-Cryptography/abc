# JavaScript SHA3-256

`Sha3_256.update(input)` absorbs byte-oriented `Uint8Array` input.
`digest()` returns an independently owned 32-byte hash and permits more updates.
The shared JavaScript Keccak core uses a 136-byte rate and the
FIPS 202 domain byte `0x06`.
[FIPS 202 §6.1](https://csrc.nist.gov/pubs/fips/202/final) · [Shared core](../../../keccak-p1600/impl/javascript)

```sh
node --test src/crypto/hash/sha3-256/impl/javascript/sha3_256.test.mjs
```

The suite checks known answers and every two-chunk split for selected
rate and padding boundaries against Node's OpenSSL provider.
It also checks snapshot ownership and state preservation for invalid inputs.
Complete JavaScript source and runtime refinement remain open.
[Shared Lean bit model](../../../keccak-p1600/spec/KeccakRound.lean)
