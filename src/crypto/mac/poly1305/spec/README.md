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
Complete source refinement and the limb-state bounds across every update
remain open. [RFC 8439 Appendix A.3](https://www.rfc-editor.org/rfc/rfc8439.html#appendix-A.3)

```sh
cargo +1.92.0 test --manifest-path tools/build/rust/Cargo.toml --locked --offline -p abc-poly1305
python -B src/crypto/mac/poly1305/spec/verify.py
lean src/crypto/mac/poly1305/spec/Poly1305Reduction.lean
```
