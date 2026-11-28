# IETF ChaCha20-Poly1305

This detached-tag research AEAD composes the ABC implementations of
ChaCha20 and Poly1305. It derives a one-time MAC key from block zero, then
uses counters 1 through `2^32 - 1` for payload blocks. Associated data and
ciphertext each receive zero padding to 16-byte boundaries, followed by
their original lengths as two little-endian 64-bit integers. Callers must
allocate a distinct nonce for every encryption under the same key.
[RFC 8439 § 2.8](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8)

The API computes a full tag before opening and writes plaintext only after
verification succeeds. The comparison combines differences across all 16
tag bytes. Complete compiled-code timing evidence and key erasure remain
outside the demonstrated scope.

Rust tests reproduce the RFC AEAD ciphertext and tag, cover the counter
limit, and check preservation of the input after changed tags, ciphertext,
and associated data.
[RFC 8439 § 2.8.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2)

## Lean composition model

The reference computes the RFC byte transcript, the counter-indexed XOR
stream and the mathematical Poly1305 tag. Its seal and open functions use
a 32-byte key, a 12-byte nonce and a 16-byte tag. Under the RFC 64-bit
length bounds, the associated data and ciphertext can be recovered
uniquely from the transcript. Lean also checks its 16-byte alignment,
the payload counter bounds, and the exact full-tag XOR/OR comparison.
The Poly1305 calculation recovers the published AEAD tag from the
published one-time key, associated data and ciphertext.
[RFC 8439 §§ 2.4–2.8](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.4)

The second model follows the Rust composition's call order. It obtains
the one-time key by XORing a zero buffer at counter zero and supplies the
six transcript chunks to the incremental MAC. It checks the tag before
any payload decryption and reports every error with the original
ciphertext. If the model's stream operation satisfies
`StreamApi.Refines` and its incremental MAC satisfies `MacApi.Refines`,
both seal and open are equivalent to the reference, including their
returned bytes and error statuses. The round-trip theorem applies to
all admitted messages. The error preservation theorem for the call
model holds even without the functional contracts.

The block function remains a parameter of this model. The linked
extraction separately checks the Rust block implementation. Applying
the composition theorem to the Rust program requires a source binding
for the AEAD call sequence and proofs of its stream and incremental MAC
contracts. Compiled timing, key erasure and cryptographic security games
remain outside the functional model.
[Rust block extraction](../../../../../tools/verification/chacha20/README.md)
· [Rust AEAD source](../impl/rust/src/lib.rs)
· [Lean source](ChaCha20Poly1305Rfc.lean)

Lean 4.31.0 checks the models. The axiom reports for the named results
admit only `propext`, `Classical.choice` and `Quot.sound`.

```sh
lean -DwarningAsError=true src/crypto/aead/chacha20-poly1305/spec/ChaCha20Poly1305Lengths.lean
lean -DwarningAsError=true src/crypto/aead/chacha20-poly1305/spec/ChaCha20Poly1305Rfc.lean
```

## Design and security literature

The original ChaCha and Poly1305 papers describe the core algorithms.
The multi-user analysis provides conditional cryptographic bounds and
identifies a flaw in the earlier single-user analysis cited by the RFC.
Applications must ensure unique encryption nonces per key.
[Bernstein, ChaCha](https://cr.yp.to/chacha/chacha-20080128.pdf)
· [Bernstein, Poly1305](https://cr.yp.to/mac/poly1305-20050329.pdf)
· [Degabriele et al., multi-user security](https://eprint.iacr.org/2023/085)
· [Procter, early analysis](https://eprint.iacr.org/2014/613)
