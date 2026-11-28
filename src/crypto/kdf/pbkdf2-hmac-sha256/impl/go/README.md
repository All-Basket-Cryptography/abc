# Portable Go PBKDF2-HMAC-SHA-256

This implementation derives arbitrary admissible output lengths using the
native ABC Go HMAC. It snapshots the keyed state and the state after absorbing
the salt, so a long password is hashed once and the salt prefix is processed
once. Block numbers begin at one and are serialized as 32-bit big-endian.
The caller owns the returned buffer and policy for work, memory, and password
handling. [RFC 8018 § 5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2)

The test suite includes RFC 7914's first PBKDF2 vector and 450 comparisons
with Go's standard library. Cases include long passwords, the salt and
output block boundaries, and the change from block index 255 to 256.
Validation checks happen before allocating an output. Full source
refinement, compiled timing and key erasure remain open.
[RFC 7914 § 11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11)

```sh
go test -C src/crypto/kdf/pbkdf2-hmac-sha256/impl/go -count=1 ./...
```
