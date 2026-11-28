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
the RFC marker follows the last live byte. The extracted `update` proof
checks exact buffering and complete-block consumption for arbitrary
incoming chunks. The one-shot theorem composes construction, update and
finalization against the RFC 8439 tag formula.
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

## Rust streaming benchmark

The paired Windows x64 runs used an Intel Core i7-12700K and Rust 1.92.0 at
`-O`. Each of three runs alternated call order over 11 batches. The table
reports the minimum and maximum of the three per-run median nanoseconds
per `authenticate` call. The baseline is commit `d1f7c88`. The 1-byte case
slowed down and the 64-byte case improved on this machine. The sample
ranges overlap for 17 B, 65 B, 1,025 B and 16 KiB.

| Input | Baseline ns | Candidate ns |
| ---: | ---: | ---: |
| 1 B | 31.6–32.0 | 32.9–33.4 |
| 17 B | 36.8–36.9 | 36.2–36.6 |
| 64 B | 41.7–43.1 | 35.2–36.2 |
| 65 B | 48.9–50.6 | 49.5–50.5 |
| 1,025 B | 420.4–422.5 | 421.6–427.6 |
| 16 KiB | 6,333.2–6,393.7 | 6,386.8–6,414.4 |

Run the same fixture from the repository root in PowerShell. It warms up
each implementation and checks both return the same tag before measuring.

```powershell
$polySource = 'src/crypto/mac/poly1305/impl/rust/src/lib.rs'
$polyBench = '.abc/poly1305-rust-paired'
New-Item -ItemType Directory -Force $polyBench | Out-Null
git show "d1f7c88:$polySource" | Set-Content "$polyBench/before.rs" -Encoding utf8
rustc +1.92.0 -O --edition 2024 --crate-name before --crate-type rlib "$polyBench/before.rs" -o "$polyBench/libbefore.rlib"
rustc +1.92.0 -O --edition 2024 --crate-name after --crate-type rlib $polySource -o "$polyBench/libafter.rlib"
rustc +1.92.0 -O --edition 2024 --extern "before=$polyBench/libbefore.rlib" --extern "after=$polyBench/libafter.rlib" tools/benchmarks/poly1305-rust-paired.rs -o "$polyBench/run.exe"
1..3 | ForEach-Object { & "$polyBench/run.exe" }
```
