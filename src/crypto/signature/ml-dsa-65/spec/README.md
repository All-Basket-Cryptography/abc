# Pure deterministic ML-DSA-65 in C

The C research API links to the original C implementation in AWS-LC 5.5.0
from the cached `aws-lc-sys` 0.44.0 archive. ABC supplies buffer and context
validation, Pure ML-DSA framing, and the deterministic mode. AWS-LC supplies
the lattice operations, encodings, hashing, key expansion and signatures.
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) · [AWS-LC distribution source](https://docs.rs/crate/aws-lc-sys/0.44.0/source/aws-lc/crypto/fipsmodule/ml_dsa/)

Public key derivation and signing accept a 32-byte seed from the caller's
approved source of key entropy. The API emits a 1,952-byte public key and a
3,309-byte signature. Verification requires those exact lengths. The caller
may pass an empty message and a binary context of up to 255 bytes. Signing
supplies `00 || byte(len(ctx)) || ctx` as the prefix and uses 32 zero bytes
for per-message randomness. Verification delegates Pure ML-DSA framing to
the provider. Signing stages the result until the provider succeeds and
clears its own expanded key copy. Valid source and output buffers can overlap.

The pinned archive SHA-256 is
`f09fae7be8bb3174e05c6afdb34199e6dc0c7c04ba9fa237b1967adfbde27483`.
On Windows x64, build the static provider with CMake, Ninja and `clang-cl`
in a Visual Studio developer environment, using these options.

```text
-DCMAKE_TRY_COMPILE_CONFIGURATION=Release -DCMAKE_BUILD_TYPE=Release
-DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DBUILD_LIBSSL=OFF -DBUILD_SHARED_LIBS=OFF
-DDISABLE_GO=ON -DDISABLE_PERL=ON -DOPENSSL_NO_ASM=ON -DENABLE_SOURCE_MODIFICATION=OFF
```

The planner's Python-only `fixtures` task checks the selected NIST case IDs,
required fields, byte lengths, source provenance and the locked fixture digest.
The native checker uses the same validation before the conformance tests.

```text
python -B src/crypto/signature/ml-dsa-65/impl/c/check.py --check-fixtures
```

For the standalone native check, pass the pinned `aws-lc` source and resulting
`crypto/crypto.lib` paths as arguments or set `ABC_AWS_LC_SOURCE` and
`ABC_AWS_LC_STATIC_LIBRARY` in the invoking shell.

```text
python -B src/crypto/agreement/ml-kem-768/impl/c/build_provider.py --archive <aws-lc-sys-0.44.0.crate> --output <short-build-directory>
python -B src/crypto/signature/ml-dsa-65/impl/c/check.py --source <aws-lc> --crypto-library <crypto.lib> --openssl <openssl.exe> --output .abc/mldsa65-native
```

The first command checks the archived source hash and prints the provider
paths for the second command. The native receipt records the linked provider
library and conformance DLL hashes. The conformance DLL is named
`abc_mldsa65_c_test.dll` and includes an expanded-key test entry point.

The tests matched the NIST FIPS 204 keyGen public key for group 2 case 26,
the exact deterministic sigGen bytes for group 3 case 41, and the verification
outcomes for group 3 cases 38 and 43. The selected cases are in
`acvp-fips204-sample.json`. The expanded signing key is accepted only by a
test build. Twelve additional cases matched the complete deterministic
signature from OpenSSL 3.5.4 and verified with both providers. The checks
also covered the 255-byte context limit, empty input, overlapping buffers,
and output preservation on error.
[Pinned NIST keyGen data](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-keyGen-FIPS204) · [Pinned NIST sigGen data](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigGen-FIPS204) · [Pinned NIST sigVer data](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204)

For the July 2026 NIST errata, the selected build encodes Pure ML-DSA's
message domain and places `μ` before encoded `w1` in the challenge hash.
It leaves AWS-LC's attempt limit at its default of 13,106 for ML-DSA-65,
above the proposed minimum of 821. The upstream configuration guard
still checks the published minimum of 814.
[NIST FIPS 204 potential updates](https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx)

Complete source refinement, rejection-sampling and leakage proofs, key erasure
over the full call chain, and FIPS or production qualification remain open.
