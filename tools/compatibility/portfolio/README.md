# Native SDK portfolio replay

The inventory lists the 20 maintained profiles in each of the 11 SDK
languages. The runner finds each non-Rust leaf's declared test commands in
the module graph and runs the Rust crates in release mode. It records a
source and build digest per cell before and after execution, each command's
exit status, and the SHA-256 of its log. A missing executable, timed-out
command or changed input leaves the result unsuccessful.
[Scope, standards and profile list](../../../docs/plan/multi-language-qualification.md)

Run the module from the repository root with Python 3.11 or later. Select
lanes whose native compilers and locked providers are available on the
host. Each leaf's README documents its tool version, platform and
third-party prerequisites. For a host with separately cached provider
crates, `ABC_PORTFOLIO_PQ_CARGO_HOME` selects their Cargo cache. Set
`ABC_PORTFOLIO_ECDSA_GO_TOOLCHAIN` if a dedicated Go version is needed for
the P-256 leaf.

```sh
python -B -m tools.compatibility.portfolio.replay --inventory
python -B -m tools.compatibility.portfolio.replay --languages rust javascript typescript --workers 3 --output .abc/portfolio-local
python -B -m tools.compatibility.portfolio.replay --verify .abc/portfolio-local
python -B -m tools.compatibility.portfolio.replay --languages swift --output .abc/portfolio-swift
```

Keep the `result.json` and command logs together. Verification checks the
complete inventory for each reported language, matches the declared
commands and source/build digests, and rejects missing or changed logs.
The receipt describes advisory execution and carries no authenticated
attestation. The release verifier has its own tool, artifact, trust-domain
and review checks.

## Native C post-quantum supplement

The C matrix's ML-KEM-768 and ML-DSA-65 gate commands check fixtures.
The supplement also builds and executes both C implementations. On
Windows x64, make Python 3.11 or later, Git, CMake, Ninja, `clang-cl` with
the Windows SDK, and OpenSSL 3.5.4 available. The recipe builds AWS-LC once
from the pinned `aws-lc-sys-0.44.0.crate` archive and links both checks to the
same static library. The ML-KEM check loads independent OpenSSL `libcrypto`
and the ML-DSA check runs independent OpenSSL CLI commands.
[C ML-KEM-768 builder and checks](../../../src/crypto/agreement/ml-kem-768/impl/c) · [C ML-DSA-65 checker](../../../src/crypto/signature/ml-dsa-65/impl/c/check.py)

```sh
python -B -m tools.compatibility.portfolio.native_pq --output .abc/portfolio-native-pq
python -B -m tools.compatibility.portfolio.native_pq --verify .abc/portfolio-native-pq
```

The default archive is selected by its SHA-256 from the Cargo registry
cache. Use `--archive` for a local copy and `--cmake`, `--ninja` or
`--compiler` to select the build tools. `--openssl` selects the CLI and
`--openssl-crypto` can specify its `libcrypto-3-x64.dll` explicitly. Supply
`--upstream` to check the two original NIST ML-KEM projections together
with the repository fixtures. The build and test commands run offline.

The result directory keeps separate leaf reports and an aggregate receipt
with their digests. The receipt records the AWS-LC source archive and
compiled library hashes, OpenSSL CLI and library fingerprints, the test
binary digests, and the worktree files used. `--verify` checks the current
checkout's input hashes, the AWS-LC pin and the leaf-report bindings.
The recorded Windows run passed eight ML-KEM ACVP cases, the RFC 9935 key
check, four randomized API round trips, eight OpenSSL interop cases and
eight implicit rejection cases. It also passed four ML-DSA ACVP cases and
twelve OpenSSL differential checks.
[Windows x64 supplement receipt](receipts/native-pq-windows-x64/result.json)
