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

Lean also checks `Abc.Refine.ChaCha20.quarter_round_refines` against the actual
Rust `quarter_round` extracted by pinned Charon and Aeneas. For every
16-word state and every four distinct in-range indices, the extracted
function succeeds and returns the RFC quarter-round state. This covers the
four updated words and the twelve preserved words. The specification
checks the RFC quarter-round known answer. Refinement of the block and
keystream API remains open. [Reproduction and scope](../../../../../tools/verification/chacha20/README.md)
