# TypeScript SHAKE256

`Shake256.update(input)` absorbs byte-oriented `Uint8Array` input.
`finalize()` returns an independent output reader. `read(size)` allocates the requested output. `readInto(output)` fills a caller-provided `Uint8Array` and advances the reader.
The shared TypeScript Keccak core uses a 136-byte rate and the
FIPS 202 domain byte `0x1f`.
[FIPS 202 §6.2](https://csrc.nist.gov/pubs/fips/202/final) · [Shared core](../../../keccak-p1600/impl/typescript)

```sh
node --test src/crypto/hash/shake256/impl/typescript/shake256.test.mts
```

The suite checks known answers and every two-chunk split for selected
rate and padding boundaries against Node's OpenSSL provider.
It also checks independent readers, output splitting and preservation after invalid reads.
Complete TypeScript source and runtime refinement remain open.
[Shared Lean bit model](../../../keccak-p1600/spec/KeccakRound.lean)
