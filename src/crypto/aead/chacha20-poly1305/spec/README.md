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
and associated data. Lean checks alignment of the authenticated stream
and bounds excluding the key-derivation counter. Complete refinement of
the two cores and their composition remains open.
[RFC 8439 § 2.8.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2)
