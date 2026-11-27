# HMAC-SHA-256 functional specification

The construction instantiates [RFC 2104 section 2](https://www.rfc-editor.org/rfc/rfc2104.html#section-2)
with the SHA-256 function of [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

Let `H` be SHA-256 on byte strings. For a key `K`, let `K0` be `K` padded to
64 bytes with zeroes when `K` is at most 64 bytes. Otherwise let `K0` be the
32-byte digest `H(K)` followed by 32 zeroes. Define `ipad` and `opad` as
64 copies of bytes `0x36` and `0x5c` respectively. For byte string `M`, the
tag is `H((K0 xor opad) || H((K0 xor ipad) || M))`. Concatenation is denoted
by `||`, and `xor` operates bytewise.

The API accepts each key length up to the byte-aligned SHA-256 domain
maximum `2^61 - 1`. The concatenated message has a maximum length of
`2^61 - 1 - 64`, which leaves room for the inner key block. Rejected input
leaves any streaming state unchanged. Successful streaming completion is
equivalent to a single call over the concatenated chunks, including empty
chunks and the empty message.

## Checked refinement

The independent [Lean specification](formal/HmacSpec.lean) implements the RFC
construction and the two byte-length errors. The checked implementation
theorems compose the exact extracted HMAC code with the separately verified
portable SHA-256 model. [Refinement theorems](formal/HmacRefinement.lean)

| Rust API | Checked behavior |
|---|---|
| `HmacSha256::new` | Normalizes admissible keys and initializes both hash streams. An over-limit key returns `KeyTooLong`. |
| `HmacSha256::update` | Appends admissible bytes to the represented message. An over-limit update returns `MessageTooLong` and preserves the entire prior state. |
| `HmacSha256::finalize` | Consumes a represented state and returns the 32-byte RFC tag. |
| `authenticate` | Returns the RFC tag or the corresponding length error, checking the key before the message. |
| Finite call traces | Finalizes the concatenation of accepted chunks in order. The concatenation corollary covers every chunk when their total length is admissible. |

Lean 4.31.0 checked these theorems and their independent statement anchors.
The seven endpoint and trace declarations use only `propext`,
`Classical.choice`, and `Quot.sound`. The independent spec also matched the
short-key and long-key vectors in RFC 4231 §§ 4.2 and 4.7. [Trusted statements](formal/HmacTrustedClaims.lean) [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html)

The local check used a modular HMAC model extracted for
`x86_64-pc-windows-msvc` with default features disabled. Charon ran with Rust
`nightly-2026-08-18`. Aeneas `nightly-2026.09.09-505b6ca` translated the model
on Linux, and the Lean checker ran on Windows. A second extraction reproduced
both model files and both external linkage templates byte-for-byte.

| Checked input | SHA-256 |
|---|---|
| HMAC `src/lib.rs` | `b9be56d2cc809e6b3998e76ec53edcaf4ccb98f19e3c2f643678f224a9f09425` |
| Generated `Abc/HmacSha256/Extracted/Types.lean` | `b5032253263920856001d66032212539fa890010b34af03490160da5f0c0ac48` |
| Generated `Abc/HmacSha256/Extracted/Funs.lean` | `1f11cef6d06576dd35715a2a8e6d6108d6562c7da4bb1437bf25b33c85102143` |

Lean rejected a scratch copy of the extracted model after its inner-key XOR
constant was changed from `0x36` to `0x37`. The failure was at the pad loop
invariant. [Pad-loop proof](formal/HmacPadRefinement.lean)

From the repository root on Linux x86-64, set `ABC_AENEAS_ROOT` to the pinned
tool checkout with the verified Aeneas and Charon executables. Run the combined
extraction and proof checker with the pinned Rust and Lean versions. [Checker source](../../../../formal/hmac-hkdf/check.mjs)

```sh
node formal/hmac-hkdf/check.mjs
```

The claim scope is byte-level functional refinement of the portable Rust
implementation. Cryptographic security, timing, memory erasure, and compiled
binary correspondence require separate evidence.
