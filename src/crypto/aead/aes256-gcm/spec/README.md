# AES-256-GCM

The portable Rust research profile uses AES-256, fixed 96-bit nonces,
and detached 128-bit tags. GHASH covers independently zero-padded
associated data and ciphertext, followed by their original lengths in
bits. The implementation rejects payloads that exhaust the 32-bit
counter and associated data that does not fit the length field.
Callers own unique nonce allocation for each key.
[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)

Opening computes and checks the full tag before writing plaintext.
The Rust tests include NIST GCM-AES256 example 5 with partial blocks,
empty input, and preservation of ciphertext on rejected authentication.
Lean checks the counter range and the logical equality result of
an OR of all tag-byte differences. Source correspondence, leakage
assessment and hardware performance qualification remain open.
[NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf)
