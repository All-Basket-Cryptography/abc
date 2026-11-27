# TypeScript SHA-512

The streaming FIPS 180-4 core runs directly in TypeScript. It accepts
a `Uint8Array` and copies any uncompressed suffix. `digest()` returns a new
64-byte result and leaves the stream open. `reset()` starts an empty stream.
The byte-domain cap is `2^125 - 1`. A big-integer byte count is used for
the 128-bit FIPS length trailer. [FIPS 180-4 §§4–6](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

The round loop implements 64-bit words using two unsigned 32-bit limbs.
A rolling 16-word schedule limits scratch space. JavaScript number
additions stay within the exact integer range before the carry and
modular reduction. [Lean limb model](../../spec/Sha512SplitWord.lean)

```sh
node --test src/crypto/hash/sha512/impl/typescript/sha512.test.mts
```

The Node test uses the OpenSSL provider as an independent oracle and
covers known answers, offset views, all splits around the padding and
block boundaries, and recoverable input errors. Source extraction and
browser/runtime correspondence remain open.
[NIST secure hashing vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing)
