# Catalog snapshot review

Run `python -m tools.abc_catalog` from the repository root to review the
[seed snapshot](snapshots/seed-2026-11-28.json). Use `--snapshot PATH` to
review a new export in the same versioned input format. The command
validates proposed records with the canonical registry schema and produces
a report without modifying tracked files.

The report records the input digest and acquisition date, coverage against
the exact declared source set, candidate additions, unchanged IDs, and
proposed changes with both versions visible. Each subject gets an expansion
task with publication references and implementation or specification work
to review. Alias and parameter relationships are validated before the
report can be generated. Bibliography records retain publication edition,
errata links, and the scope of redistribution rights.

The seed covers eight subjects across classical cryptography, mainstream
hashing, post-quantum cryptography, zero knowledge, two-party privacy
protocols, and fully homomorphic encryption. The canonical registry contains
these eight metadata entries. Their implementation and proof coverage is
tracked separately. [NIST post-quantum publications](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/publications)
[IACR Groth paper](https://eprint.iacr.org/2016/260)
[RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html)
