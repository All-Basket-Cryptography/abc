# AES-256-GCM

The portable Rust research profile uses AES-256, fixed 96-bit nonces,
and detached 128-bit tags. GHASH covers independently zero-padded
associated data and ciphertext, followed by their original lengths in
bits. The implementation rejects payloads that exhaust the 32-bit
counter and associated data that does not fit the length field.
Callers own unique nonce allocation for each key.
[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)

Opening computes and checks the full tag before writing plaintext.
The Rust tests cover NIST GCM-AES256 example 5 with partial blocks,
empty input, and ciphertext preservation for all 128 single-bit tag changes.
[NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)

## Checked composition

The Lean reference uses the GHASH multiplication recurrence in
SP 800-38D Algorithm 1, the GHASH fold in Algorithm 2, and the counter
mode and authentication operations from Algorithms 3–5. It fixes the
profile at 96-bit nonces and 128-bit tags. The implementation model
follows the portable Rust functions' shifts and masks, counter chunks,
separate GHASH updates, packed length word, and detached seal and open
control flow. [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
· [Lean source](Aes256GcmComposition.lean) · [Portable Rust source](../impl/rust/src/lib.rs)

Lean proves the 128 multiplication rounds agree for every operand pair.
It proves zero padding and exact packing of both 64-bit big-endian bit
lengths. Under these length bounds, the authenticated transcript
uniquely encodes the associated data and ciphertext. The independently
padded incremental GHASH updates agree with processing that transcript
in one pass. The counter proof covers every payload byte and the
byte-level stream agrees with 16-byte chunks followed by a partial
chunk. Counters zero and one stay outside the payload domain.

The full-tag XOR/OR reduction equals exact 16-byte comparison. Given
`AesApi.Refines`, which requires the block provider to return the
reference AES-256 block value for every key and block, modeled seal and
open agree with the reference for both accepted and rejected inputs.
The round trip covers every admitted plaintext. The model preserves
caller bytes on errors even without the AES contract. Lean also checks
the GHASH value, ciphertext, tag and decrypted plaintext of NIST
example 5 using its published AES block outputs.

Charon and Lean additionally check the portable Rust source for GHASH
multiplication, block absorption, length packing and the final tag word.
They check both APIs' length gate and the complete CTR transform through the
counter, nonce/counter serialization and per-byte XOR, under the AES block
and Rust standard library contracts. The open gate compares the whole tag, returns
`AuthenticationFailed` without decrypting a mismatched tag, and reaches
payload decryption only after a match.
The composition uses the Lean slice and padding model to supply the
blocks, and AES block values to supply the hash key and tag mask.
Source-level proofs for GHASH slice traversal and conversion, the concrete
AES provider and the full seal path remain open. Compiler
timing, binary correspondence, key erasure, nonce allocation and
cryptographic security games require separate evidence.
[Rust source refinement and replay](../../../../../tools/verification/aes256-gcm/README.md)

Run the models with Lean 4.31.0. The 20 composition results report only
the standard axioms `propext`, `Classical.choice` and `Quot.sound`.

```sh
lean -DwarningAsError=true src/crypto/aead/aes256-gcm/spec/Aes256GcmBounds.lean
lean -DwarningAsError=true src/crypto/aead/aes256-gcm/spec/Aes256GcmComposition.lean
```

## Design literature

FIPS 197 specifies the AES block cipher. The original GCM analysis gives
the mode design and its conditional security and performance analyses.
SP 800-38D Appendix A discusses assurance of IV uniqueness and Appendix B
discusses authentication assurance.
[NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)
· [McGrew and Viega, GCM security and performance](https://eprint.iacr.org/2004/193)
· [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
