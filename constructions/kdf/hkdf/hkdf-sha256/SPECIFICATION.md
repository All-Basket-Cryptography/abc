# HKDF-SHA-256 functional specification

Use HMAC-SHA-256 with complete 32-byte tags to instantiate
[RFC 5869 sections 2.2 and 2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2).
The [RFC Editor record](https://www.rfc-editor.org/info/rfc5869/) links
published errata.

Extract maps a salt and an input byte string to a 32-byte pseudorandom key
by evaluating `HMAC(salt, input)`. If the salt is absent, its effective
value is 32 zero bytes. An explicitly empty salt has the same effective
HMAC key block.

For expansion, let `K` be the pseudorandom key of at least 32 bytes, `I` the
byte string `info`, and `L` the output length from 0 through 8160 bytes.
Let `T0` be empty. For `i` from 1 through `ceil(L / 32)`, let `Ti` be
`HMAC(K, T(i-1) || I || byte(i))`. Return the first `L` bytes of the
concatenation of the generated blocks. For `L = 0`, return the empty string.
The HMAC key and message lengths must remain inside that function's domain.
The API rejects an invalid length before changing the caller's output buffer.

## Checked refinement

`HkdfSpec.lean` defines the RFC byte recurrence and the public length
contract. Key lengths below 32 or above the HMAC limit take precedence
over the output limit. An accepted zero-length output skips the info
length check. Every other output reserves one counter byte and, when
there is more than one block, the 32-byte preceding tag.

`HkdfApi.lean` proves the extracted Rust `extract`, `expand`, `derive`,
`Prk::as_bytes`, and `Prk::expand` against that specification.
`ExpandRefinement.lean` proves that the expansion loop terminates, fills
the requested prefix, and reaches the 255th counter block without
wrapping. The API theorems prove exact preservation of the caller's
output on every error, including an extraction error during `derive`.
`HkdfClaims.lean` checks the expected statements independently of the
implementation proof. [Extraction, toolchain and audit](../../../../formal/hmac-hkdf/README.md)

This refinement covers functional behavior. Output security depends on
the properties of the input keying material and on management of context
and salt.
