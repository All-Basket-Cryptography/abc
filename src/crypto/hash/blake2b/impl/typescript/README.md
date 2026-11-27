# TypeScript BLAKE2b

`blake2b(input, length = 64)` computes the unkeyed sequential digest with an
output length from 1 through 64 bytes. `new Blake2b(length).update(input).digest()`
supports incremental byte arrays and non-consuming digest snapshots. The
output length binds the parameter block. The last full block stays buffered
until more input arrives or the caller requests the digest. Input uses a
`Uint8Array` backed by an `ArrayBuffer`, and each digest owns its bytes.

Every 64-bit compression word is represented by two unsigned halves. The
counter uses a 128-bit-bounded BigInt and compression uses byte-order-explicit
data loads. Published answers, CPython's independent BLAKE2b implementation for
all 64 digest lengths and the Node/OpenSSL full-output oracle cover the profile.
The Lean buffer model and shared split-word arithmetic support the design.
Original-source refinement and target timing remain open.

```sh
node --test src/crypto/hash/blake2b/impl/typescript/blake2b.test.mts
```

Use Node.js 24 and Python 3, or set `ABC_PYTHON` to the desired Python
executable.

On Windows x64 with an i7-12700K and Node 24.12.0, a 1 MiB one-shot
digest reached 66.0 MiB/s. Node's OpenSSL 3.5.4 provider reached
1,272.1 MiB/s under the same five-trial median with 15 calls per trial.

- [RFC 7693 §§ 2–3 and Appendix A](https://www.rfc-editor.org/rfc/rfc7693.html)
- [BLAKE2 design paper](https://eprint.iacr.org/2013/322)
- [Lean final-block model](../../spec/Blake2bBuffer.lean)
