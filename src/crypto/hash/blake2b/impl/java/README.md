# Java BLAKE2b

The native Java implementation covers unkeyed sequential BLAKE2b with
digest sizes of 1–64 bytes. `new Blake2b(size)` binds the digest size into
the initial parameter block. The default constructor selects 64 bytes.
`update` accepts full arrays and checked ranges. `digest` returns
caller-owned bytes and leaves the absorber available for further input.
`reset` keeps the selected digest size. `Blake2b.hash(input, size)` is the
one-shot API.
[RFC 7693 §§2–3](https://www.rfc-editor.org/rfc/rfc7693.html#section-2)

The 128-bit byte counter uses two unsigned 64-bit limbs. Range or counter
errors preserve the state. A full pending block stays buffered until
more input arrives or a snapshot applies the final-block flag. The core
reads 64-bit words in little-endian order and reuses scratch words
throughout each update.

Run with JDK 17, Python and Node. The checker compiles with `--release
17`, `-Xlint:all` and `-Werror` and builds a separate consumer against
the standalone JAR. Pass `--output` to retain the tested JAR and receipt.

```sh
python -B src/crypto/hash/blake2b/impl/java/check.py
```

JDK 17.0.12 on Windows amd64 matched the RFC `abc` digest, 576 outputs
from CPython 3.13.14 covering all 64 digest sizes, and 6,486 two-chunk
traces. The corresponding nine 64-byte digests also matched OpenSSL
3.5.4 via Node 24.12.0. Tests cover full final blocks, snapshots, caller
buffer reuse, malformed ranges, and the 128-bit counter limit.
[RFC 7693 Appendix A](https://www.rfc-editor.org/rfc/rfc7693.html#appendix-A)

On an Intel Core i7-12700K, a one-shot 4,096-byte message with a
64-byte digest had a median of 7.820 µs with the tested JAR and
4.242 µs with Node/OpenSSL. Each interface ran three 20,000-call
batches after 5,000 warm-up calls.

The existing Lean model checks final-block buffer arithmetic. Exact
Java source refinement and compiled leakage evidence remain open.
[Lean buffer model](../../spec/Blake2bBuffer.lean)
