# Portable JavaScript SHA-256

`sha256.mjs` implements byte-oriented SHA-256 directly in JavaScript. The
compressor updates a circular 16-word schedule as the rounds consume it.
`sha256(input)` and the `Sha256` streaming context accept `Uint8Array` input.
`digest` returns a fresh byte array and preserves the open context. `reset`
starts a fresh message. The byte counter is a `BigInt` and rejects overflow
before changing state. [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

Node 24.12.0 on Windows amd64 passed four fixed digests, 1,052 boundary splits,
256 seeded binary inputs checked against Node's SHA-256, and buffer, snapshot,
invalid-input and reset checks. [NIST worked examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf) · [RFC 6234 test vectors](https://www.rfc-editor.org/rfc/rfc6234.html#section-8.5)

```sh
node --test src/crypto/hash/sha256/impl/javascript/sha256.test.mjs
```

Source-level refinement, browser qualification and SDK integration remain open.

## Public-input timing

On Node 24.12.0 with an Intel Core i7-12700K running Windows amd64, five warmed
batches of one-shot calls had a median of 2.23 µs at 64 bytes and 70.0 µs at
4,096 bytes. Node's native `createHash('sha256')` took 1.03 µs and 2.71 µs
on the same inputs. The raw measurements use 30,000 and 3,000 digests per batch.
