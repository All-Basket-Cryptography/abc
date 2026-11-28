# Poly1305

Poly1305 authenticates a byte string using a **one-time** 32-byte key.
The implementation clamps the first half, absorbs 16-byte blocks with an
appended one bit, reduces modulo `2^130 - 5`, and adds the second half
modulo `2^128` to produce a 16-byte tag. The caller must supply a fresh key
for each message. The AEAD construction derives that key from its unique
nonce. [RFC 8439 §§ 2.5–2.6](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5)

The Rust core stores five 26-bit limbs and selects the final reduction with
a mask. The division-free inner loop uses fixed key-independent indexing.
The compiled leakage behavior and key lifetime require target evidence.

Rust tests check the RFC example and seven RFC reduction vectors at every
split point, as well as empty input and a zero multiplier. The independent
Python oracle uses arbitrary-precision integer arithmetic at block boundaries
and across 2,000 seeded random inputs. Lean checks high-term folding, the
final-reduction threshold and a sum bound under its stated input hypotheses.
The extracted Rust core has checked proofs for little-endian byte loading,
key clamping, caching the key multiples, and full-block absorption including
the appended one bit. It also proves the absorption step for an already
padded final block and the normalization that precedes final reduction.
The absorption theorems require a live accumulator and bounded key limbs
with a correct cache. Each step preserves that limb range and advances the
RFC polynomial recurrence modulo `2^130 - 5`. For any live accumulator
and 128-bit pad, the extracted `finish_tag` helper used by `finalize`
performs the final conditional subtraction, packs the low 128 bits, adds
the pad, and emits the exact 16 little-endian tag bytes.

The public constructor now has a source proof for key splitting, clamping,
pad loading and the initial empty state. The source proof of the public
finalizer covers both an empty pending buffer and a partial final block.
It verifies that bytes past the buffered prefix have no effect and that
the RFC marker follows the last live byte. The public `update` loop and
its composition with one-shot `authenticate` still need a source proof.
The source replay compiles the exact generated model and audits the theorem
dependencies. [Source verification](../../../../../tools/verification/poly1305/README.md) ·
[RFC 8439 Appendix A.3](https://www.rfc-editor.org/rfc/rfc8439.html#appendix-A.3)

The 13-bit radix model for the JavaScript and TypeScript carry equations
proves congruence modulo `2^130 - 5`, a bound below 34 bits for propagated
columns, and normalization after the exact three sweeps used by their
implementations. Its hypotheses require ten input columns below `2^33`.
The folded-term and ten-term bounds cover construction of such columns
from digits below twice the radix and key limbs below the radix.
The model leaves decoding, final tag serialization, source translation,
and JavaScript runtime timing open.

```sh
cargo +1.92.0 test --manifest-path tools/build/rust/Cargo.toml --locked --offline -p abc-poly1305
python -B src/crypto/mac/poly1305/spec/verify.py
lean src/crypto/mac/poly1305/spec/Poly1305Reduction.lean
lean -DwarningAsError=true src/crypto/mac/poly1305/spec/Poly1305Radix13.lean
```
