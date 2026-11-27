# ML-KEM-768

The C research API uses the pinned AWS-LC 5.5.0 native C implementation of
ML-KEM-768. It returns the 1,184-byte raw encapsulation key, 2,400-byte
expanded decapsulation key, 1,088-byte ciphertext and 32-byte shared
secret. Production entry points use provider randomness. The fixture
build admits the FIPS 203 deterministic inputs `d || z` and `m`.
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)

The provider checks the modulus encoding of an encapsulation key and the
embedded public-key digest of a decapsulation key during the operation.
The C adapter checks sizes first and preserves output on an operation
error. A correctly sized ciphertext that fails reencryption yields the
implicit-rejection secret. Callers keep raw decapsulation keys and shared
secrets private and manage their lifetimes.

The NIST errata list clarifies the array alignment role of the zero
entry in Appendix A and the variable name in the comment on Algorithm
15, line 7. Both entries are explanatory for these conformance cases.
[FIPS 203 errata](https://csrc.nist.gov/files/pubs/fips/203/final/docs/fips-203-potential-updates.xlsx)

## Fixed sources and vectors

The offline build verifies `aws-lc-sys-0.44.0.crate` before extraction.
Archive SHA-256 is
`f09fae7be8bb3174e05c6afdb34199e6dc0c7c04ba9fa237b1967adfbde27483`.
The crate records revision `f464440d1fd3983ce9fb023e9eaf1698530919a2`.
The checker builds the provider as a static Windows x64 library using
its portable C configuration and links a separate C17 consumer.
[Pinned crate](https://crates.io/crates/aws-lc-sys/0.44.0)

The fixture selection contains keyGen group 2 cases 26 and 27,
encapDecap group 2 cases 26 and 27, group 5 cases 86 and 88, group 9 case
128 and group 10 case 137. The checked-in projection records the source
URLs and SHA-256 of both original files at NIST revision
`975de31eb83d87039ec88934fdc47d8c312b892d`. Group 5 case 88 specifies an
implicit-rejection result. The last two cases check rejection of a
decapsulation key with the wrong embedded-key digest and an
encapsulation key with a noncanonical encoding. The C harness checks
that rejection preserves the destination in both cases.
[NIST ACVP data](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files)

The pinned provider archive includes the RFC 9935 Appendix C seed
`00..3f` and example keys. The harness compares the raw key payloads
with the embedded SPKI and expanded PKCS#8 examples.
[RFC 9935 Appendix C](https://www.rfc-editor.org/rfc/rfc9935.html#appendix-C)

## Reproduce the checks

Run in a Windows x64 developer shell with Python 3.13, CMake, Ninja,
Clang-cl and OpenSSL 3.5.4. The checker uses the pinned local Cargo
cache or an explicitly supplied archive. Pass `--cmake`, `--ninja`
or `--compiler` for tools outside `PATH`. The default OpenSSL oracle
is the Git for Windows OpenSSL DLL, configurable with
`--openssl-crypto`. A short writable `--work-root` avoids the Windows
path limit in the native build.

```sh
python -B src/crypto/agreement/ml-kem-768/spec/fixtures.py
python -B src/crypto/agreement/ml-kem-768/impl/c/check.py --archive <local-archive>
```

Give either checker `--upstream` with a directory containing the
pinned original ACVP JSON files to compare the projection to its
sources. `build_provider.py --output <new-short-directory>` retains a
separately reproducible provider build. The Planner runs the fixture
check. Native compilation and oracle comparison run in the developer
environment.

The native suite runs eight selected ACVP cases, an RFC 9935 vector,
eight independent OpenSSL 3.5.4 key generation, encapsulation and
decapsulation comparisons, eight same-length implicit-rejection checks,
and four randomized production API roundtrips. Source refinement, FIPS
module qualification, compiled-target timing and performance evidence
remain open.
[OpenSSL ML-KEM provider](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/)
