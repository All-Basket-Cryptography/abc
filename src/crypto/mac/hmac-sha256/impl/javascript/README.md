# HMAC-SHA-256 in JavaScript

`hmac.mjs` implements HMAC with the ABC JavaScript SHA-256 core. It
normalizes keys larger than the 64-byte SHA-256 block with the local hash.
`authenticate` returns the full 32-byte tag. `HmacSha256` supports incremental
updates, non-destructive tag snapshots and reset under the same key.
It precomputes the compressed inner and outer key states once per context
and copies them when resuming. Treat a saved state as key material.
[RFC 2104 § 4](https://www.rfc-editor.org/rfc/rfc2104.html#section-4)

The tests use RFC 4231 cases 1 and 6 and compare 35 key/message length pairs
with the host cryptographic library. They include empty and split updates,
caller-buffer mutation, invalid input, and repeated snapshots with interleaved keys.
[RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html#section-4)

```sh
node --test src/crypto/mac/hmac-sha256/impl/javascript/hmac.test.mjs
```

Source-level refinement, side-channel evaluation, key erasure and production
qualification remain open.

## Public-input timing

The paired benchmark gives timings for one-shot and same-key workloads
against the previous portable implementation and Node OpenSSL.
[Public-input data](../../../../../../docs/status/hmac-prepared-ecmascript-benchmark.json)
