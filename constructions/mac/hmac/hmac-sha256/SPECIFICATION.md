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

The refinement target is equality with this 32-byte tag for the accepted
one-shot and streaming domains, plus fail-atomic rejection of overflow.
The security properties assumed by applications, compiler behavior, and
memory state are separate claims.
