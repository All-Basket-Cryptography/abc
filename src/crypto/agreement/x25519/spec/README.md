# X25519

`abc-x25519` implements the 32-byte X25519 public-key and Diffie–Hellman
operations in portable Rust. It takes the caller's private bytes, clamps
the scalar, masks bit 255 of the peer's u-coordinate and accepts RFC
noncanonical encodings. `shared_secret` returns `InvalidPeer` if all 32
result bytes are zero. The calling protocol supplies fresh private material
from a cryptographic RNG, authenticates the exchange and uses a KDF with the
required transcript binding. [RFC 7748 §§5–7](https://www.rfc-editor.org/rfc/rfc7748.html#section-5)

The implementation uses five radix-2^51 limbs, wide integer products and
masked swaps in a fixed 255-step Montgomery ladder. Lean checks the modular
high-term fold, canonical-reduction threshold and an accumulator bound.
Source-to-specification refinement of the carries, inversion and ladder
is open. The compiled timing and key-erasure properties have no target
qualification. [Curve25519 paper](https://iacr.org/cryptodb/archive/2006/PKC/3351/3351.pdf)

From the repository root, run the RFC iteration and Alice/Bob vectors,
encoding and low-order cases, OpenSSL comparisons and Lean checks.

```sh
cargo +1.92.0 test --manifest-path tools/build/rust/Cargo.toml --locked --offline --release -p abc-x25519
node src/crypto/agreement/x25519/spec/verify.mjs
lean src/crypto/agreement/x25519/spec/X25519Field.lean
```
