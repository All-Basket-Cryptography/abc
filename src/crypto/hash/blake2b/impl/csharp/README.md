# Portable C# BLAKE2b

`Abc.Cryptography.Blake2b` targets .NET 10. The managed core implements
the sequential, unkeyed BLAKE2b profile with 1–64-byte digests. The
parameter word binds the requested digest size. The final block,
including an exact 128-byte block, stays pending until the caller adds
more input or requests a digest. Compression uses little-endian words,
12 rounds and a 128-bit byte counter.
[RFC 7693 §§2–3](https://www.rfc-editor.org/rfc/rfc7693.html#section-2)

Use `Blake2bHasher` for a streaming digest. The constructor defaults
to 64 bytes and throws `ArgumentOutOfRangeException` for a size outside
the profile. `Update` absorbs bytes without holding the input span.
`Digest` snapshots to a span of exactly `DigestSize` bytes. `Reset`
starts a fresh stream at the same size. Serialize operations on a
shared context. `Blake2bHasher.Hash` selects the digest size from the
destination length and permits overlapping input and output spans.
An invalid buffer size preserves the output. A counter overflow
preserves the stream.

```csharp
using Abc.Cryptography;

Span<byte> digest = stackalloc byte[32];
Blake2bStatus status = Blake2bHasher.Hash("abc"u8, digest);
```

The verifier packs the managed library and restores an external
consumer from a temporary local feed using the pinned .NET SDK
10.0.404. On Windows x64, the checked Release build passed five
published known answers, 139 OpenSSL 3.0.21 comparisons, 697 CPython
3.13.14 `hashlib.blake2b` comparisons, 841 prefix snapshots and 4,926
two-chunk splits. The suite also checks the 128-bit counter carry and
overflow, reset, buffer bounds and overlapping spans. Lean proves
final-block retention in the buffer model. Managed source refinement,
compiled-target timing analysis and performance results for additional
targets remain open.
[RFC 7693 Appendix A](https://www.rfc-editor.org/rfc/rfc7693.html#appendix-A) · [BLAKE2 project known answers](https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json) · [Lean buffer model](../../spec/Blake2bBuffer.lean) · [BLAKE2 design paper](https://www.blake2.net/blake2_lncs.pdf)

On an Intel Core i7-12700K, the median throughput for 1 MiB inputs at
the 64-byte output size was 733 MiB/s for the managed implementation
and 1,166 MiB/s for OpenSSL through CPython. The managed one-shot
hash allocated zero bytes on the calling thread during these batches.

```sh
python -B src/crypto/hash/blake2b/impl/csharp/check.py
python -B src/crypto/hash/blake2b/impl/csharp/check.py --benchmark
```
