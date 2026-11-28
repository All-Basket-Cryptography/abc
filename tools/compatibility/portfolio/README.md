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
attestation. Use the documented
native provider checks for the two C post-quantum profiles as well. The
regular graph tasks for those two profiles can run without their AWS-LC
native link. This is a research execution receipt. The release verifier
has its own tool, artifact, trust-domain and review checks.
[C ML-KEM-768](../../../src/crypto/agreement/ml-kem-768/impl/c) · [C ML-DSA-65](../../../src/crypto/signature/ml-dsa-65/impl/c)
