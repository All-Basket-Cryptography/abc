# Managed C# SHA-256

`Sha256Hasher.cs` implements byte-oriented SHA-256 using managed spans,
explicit byte order, and unsigned 32-bit round arithmetic. The API provides
`Update`, a non-consuming `Digest`, `Reset`, and one-shot `Hash`. Hash
operations write the first 32 destination bytes. A short destination or a
message exceeding `2^61 - 1` bytes is rejected before changing the affected
state or output. The context retains no caller spans. Calls on one context
must be serialized. [FIPS 180-4, August 2015](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)

## Reproduction

From the repository root, run these commands with the pinned .NET SDK
10.0.404 on `PATH`. The `--dotnet` option accepts an explicit SDK executable.
Use `--output` to retain the tested research package.

```text
python src/crypto/hash/sha256/impl/csharp/check.py
python src/crypto/hash/sha256/impl/csharp/check.py --benchmark
```

The check builds `Abc.Cryptography.Sha256.0.1.0.nupkg` and installs it in a
separate consumer through a fresh offline NuGet feed. The only package
binary is the `net10.0` managed assembly. On Windows x64, SDK 10.0.404 and
runtime 10.0.15 passed four known-answer cases, 151 seeded comparisons
against `System.Security.Cryptography.SHA256.HashData`, 155 oracle-checked
prefix snapshots, and 2,102 two-chunk splits. The checks also exercise
overlapping input and output, destination size, reset, caller-buffer
ownership, and length rejection by setting the test instance's internal
counter to its limit. The build checks arithmetic overflow outside the
explicit modulo-`2^32` compression. Numeric execution coverage remains open.
[NIST `abc` worked example](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/sha256.pdf) · [CAVP byte vectors](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) · [RFC 6234 § 8.5](https://www.rfc-editor.org/rfc/rfc6234.html#section-8.5)

| Input or artifact | SHA-256 |
| --- | --- |
| `Sha256Hasher.cs` | `ffa3ffe7488daeb696623585ff55dbfcfbcb3f887b3a4ae391c944c7ed93c49b` |
| `tests/Program.cs` | `aa23263e989ddd1271e94ebeda29c98799b6f5d4b059ccd752ca0e10ab021a5e` |
| First tested NuGet archive | `113b027ec6221c9d4c929a0933dfeb837f3a981efd598db8796c8760e32a9f22` |

The release configuration measured a median of 302.34 MiB/s on one Windows
x64 host with Intel Family 6 Model 151. It hashed a fixed 1 MiB message for
four warm-up calls, followed by seven timed batches of 16 calls. Batch
throughput ranged from 295.06 to 304.54 MiB/s. The benchmark rebuilt and
retested the package. Its archive digest differed from the first build.

The formal target includes managed spans and array bounds, explicit overflow
semantics, and the relationship between C# source, its fixed SDK output, and
the runtime. Checked source refinement, artifact reproducibility, and
target-specific leakage evidence remain open. [Lean SHA-256 specification](../../spec/Sha256Spec.lean)
