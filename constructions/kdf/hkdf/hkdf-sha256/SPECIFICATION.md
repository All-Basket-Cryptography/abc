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

The refinement targets are functional equality for extract and expand over
the accepted byte domain, including length 0 and the 255th counter block,
and preservation of the output buffer upon length errors. The security of
the output depends on how the supplied keying material was generated and
how context and salt are managed. Refinement does not settle those claims.
