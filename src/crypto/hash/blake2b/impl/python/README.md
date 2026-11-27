# Python BLAKE2b

`blake2b(data, digest_size=64)` returns a one-shot digest. A
`Blake2b(digest_size)` context provides `update(data)`, a non-destructive
`digest()` snapshot and `reset()` with the same digest size. The
implementation covers unkeyed, sequential messages, digest sizes
of 1–64 bytes, and one-dimensional buffers with one-byte items.
The digest size is incorporated into the initial parameter block.
[RFC 7693 §§2–3](https://www.rfc-editor.org/rfc/rfc7693.html#section-2)

The implementation uses Python integers reduced modulo `2**64` for
word arithmetic and checks the `2**128 - 1` byte message bound before
updating the state. A complete final block remains pending so its
compression includes the final flag. Caller-owned input can be reused
after an update, including when the original input was a strided view.

Copy `abc_blake2b.py` to the consumer's import directory with Python 3.10
or newer. The module uses the Python standard library.

```sh
python -B -m unittest discover -s src/crypto/hash/blake2b/impl/python -p test_blake2b.py -v
```

The test checks the final digest from the RFC `abc` example and compares 576 one-shot outputs and
6,486 split traces against CPython `hashlib.blake2b`. It also exercises
snapshots, rejected shape and size arguments, reset and counter overflow.
A separately copied Python `-I` consumer passed. The Lean buffer model
checks the final-block arithmetic. Source-to-model refinement and
runtime timing assurance remain open.
[RFC 7693 Appendix A](https://www.rfc-editor.org/rfc/rfc7693.html#appendix-A) · [Lean buffer model](../../spec/Blake2bBuffer.lean)

On Windows amd64 with CPython 3.13.14, the median of three `timeit.repeat`
batches for a 4,096-byte message and a 64-byte digest was 2.376 ms for
ABC and 4.340 µs for the compiled `_blake2` provider used by `hashlib`. Batches
used 100 pure Python calls and 12,000 provider calls respectively.
