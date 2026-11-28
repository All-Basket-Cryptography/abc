# IETF ChaCha20

The portable Rust research primitive implements the 256-bit key, 96-bit
nonce and 32-bit initial block counter in RFC 8439. It uses 20 rounds with
wrapping 32-bit addition, XOR, and rotations. The API XORs the keystream
into caller storage. All length and counter validation precedes writes.
[RFC 8439 §§ 2.1–2.4](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.1)

The protocol owns unique nonces for each key and message authentication.
This module exposes the stream primitive for research composition. Target
leakage, compiler correspondence, key lifetime and AEAD composition
require separate evidence. [RFC 8439 § 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-4)

The tests exercise the RFC block and multi-block cipher vectors and the last
counter boundary. Lean checks block-count coverage, that every admitted
counter index fits 32 bits, and the single-block limit at the last
counter.

Pinned Charon and Aeneas extract `initial_state` and `block` from the active
Rust keystream implementation. Lean proves that every 32-byte key,
12-byte nonce and 32-bit counter produce the exact 64-byte RFC block.
The proof covers little-endian input decoding, constants, all twenty
rounds, counter placement, sixteen wrapping additions and every output
byte. A sequential stream model proves that each prefix changes precisely
its traversed bytes, that counter exhaustion is exact and preserves caller
bytes, and that the complete buffer matches the RFC byte-address formula.
The model composes with the exact extracted block theorem. The Rust
standard-library iterator correspondence, target leakage and AEAD
composition have separate proof obligations.
[Reproduction and scope](../../../../../tools/verification/chacha20/README.md)
