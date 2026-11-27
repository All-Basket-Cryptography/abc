# Portable TypeScript SHA-256

`sha256.mts` implements SHA-256 with a 64-word expanded schedule and a rotating
index into its eight working registers. The typed `sha256` function and `Sha256`
streaming context accept `Uint8Array`. Digest snapshots return newly owned bytes,
and `update` keeps an internal copy of its pending suffix. The context checks
the byte counter before changing state and can be reset for another message.
[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

Node 24.12.0 on Windows amd64 passed four fixed digests, 1,710 boundary splits,
256 seeded inputs and intermediate snapshots checked against Node's SHA-256,
and ownership, rejection and reset checks. TypeScript 5.9.3 checked the source
with `--strict`. [NIST worked examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf) · [RFC 6234 test vectors](https://www.rfc-editor.org/rfc/rfc6234.html#section-8.5)

```sh
node --test src/crypto/hash/sha256/impl/typescript/sha256.test.mts
tsc --noEmit --strict --module NodeNext --target ES2022 src/crypto/hash/sha256/impl/typescript/sha256.mts
```

Source-level refinement, browser qualification and SDK integration remain open.

## Public-input timing

On Node 24.12.0 with an Intel Core i7-12700K running Windows amd64, five warmed
batches of one-shot calls had a median of 2.85 µs at 64 bytes and 57.3 µs at
4,096 bytes. Node's native `createHash('sha256')` took 1.03 µs and 2.71 µs
on the same inputs. The raw measurements use 30,000 and 3,000 digests per batch.
