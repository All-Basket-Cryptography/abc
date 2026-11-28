# HMAC-SHA-256 in Python

`abc_hmac_sha256.py` implements HMAC with the ABC python SHA-256 core. It
normalizes keys larger than the 64-byte SHA-256 block with the local hash.
`authenticate` returns the full 32-byte tag. `HmacSha256` supports incremental
updates, non-destructive tag snapshots and reset under the same key.
[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html)

The tests use RFC 4231 cases 1 and 6 and compare 35 key/message length pairs
with the host cryptographic library. They include empty and split updates,
caller-buffer mutation and invalid input.
[RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html#section-4)

```sh
python -B -m unittest discover -s src/crypto/mac/hmac-sha256/impl/python -p test_hmac.py
```

Source-level refinement, side-channel evaluation, key erasure and production
qualification remain open.

## Public-input timing

On CPython 3.13.14 and a Windows x64 i7-12700K workstation, the median of five
warmed batches was 2.11 ms per call with a 64-byte key and 1,024-byte message.
The median for the native-backed oracle on the same workload was 2.24 µs.
