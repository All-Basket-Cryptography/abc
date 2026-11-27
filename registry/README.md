# ABC catalog

Files under this directory are canonical identity and provenance records in the JSON-compatible subset of YAML 1.2. Put one record in each `.json` file and validate from the repository root with `python -m tools.abc_cli registry validate --strict`. Built artifacts and verification results need separate records with scoped evidence.

This is an initial, source-linked snapshot. The entries index historical rotor ciphers, deprecated security properties, standardized cryptography, and experimental designs. Use the cited editions and sections for source material. This snapshot redistributes bibliographic metadata and ABC descriptions. Source documents and upstream code are linked.

The catalog reserves independent identities for parameter sets, cryptographic algorithms, compositions, and protocols. The taxonomy spans classical, symmetric, hash and XOF, MAC and PRF, KDF and password, randomness, key agreement and KEM, public-key encryption, signatures, commitments and authenticated structures, VRF and VDF, secret sharing and threshold, zero knowledge, MPC and privacy, homomorphic encryption, constructions, protocols, and cryptanalysis. Many domains are still unpopulated. The count of indexed entries measures this snapshot's size.

An `indexed` or `archived` record describes catalog coverage. Implementation availability and maintenance come from linked implementation records. A subject with no such record has no registered implementation. A subject with no evidence result has no registered proof or test claim. Use policy and release approval require separate, versioned records.

The catalog links source snapshots for Go's standard-library SHA-256, the OpenSSL C SHA-256 core, and RustCrypto's Rust implementation. Each record names the release, original source language, license, and exact scope of the recorded source digest. These upstream records carry the `catalog-only` maintenance state. No upstream source has been copied into this snapshot.
