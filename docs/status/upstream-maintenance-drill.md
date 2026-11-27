# Upstream inventory and migration drill

Run from the repository root.

```sh
python -m tools.catalog.abc_upstream inventory
python -m tools.catalog.abc_upstream compare --previous .abc/previous-upstream.json
python -m tools.catalog.abc_upstream affected --implementation abc:implementation:sha256-golang-1-24-4 --revision go1.24.4
python -m tools.catalog.abc_upstream drill
```

Save the previous inventory as JSON before updating the reviewed catalog. The
inventory includes fixed revisions, original language, licenses, source digests,
maintenance assignments, and existing advisories. The comparison reports
added, removed, and changed IDs. Scheduled advisory retrieval and upstream
notifications remain pending.

Query the public feed for the reviewed RustCrypto package mapping.

```sh
python -m tools.catalog.abc_upstream osv-snapshot --implementation abc:implementation:sha256-rustcrypto-0-10-9
```

The query records advisory IDs, the exact package version, retrieval time,
and a digest of the response. The November 28, 2026 Taipei observation
returned an empty advisory list for `sha2` 0.10.9 from this feed. A later
response needs its own snapshot and review before entries are mapped to
affected releases. [Recorded response summary](upstream-osv-sha2-0.10.9.json)
[OSV query API](https://google.github.io/osv.dev/post-v1-querybatch/)

The affected-release query walks registered packages through their binding
to the exact implementation ID. A package can carry its historical
`implementation_revision`, `build_target_ref`, and `features`. Input filters
match literal revisions and target IDs, and a feature filter requires every
listed feature. Use `--advisory ABC_ID` to use a registered public advisory's
scope. A package whose recorded scope proves a match appears in `affected`.
When a needed field is missing, the query puts a potential match in
`needs_review` so an operator can inspect the source snapshot and artifact.

## Rehearsal scope

The drill models a fictional upstream provider with an affected
`optimized` feature at revision `1.4.0`, a portable replacement on that
branch, a provider replacement at revision `2.0.0`, and one historical
release missing its implementation revision. The release and advisory
records exist only in the drill. Expected results are one exact affected
release, exclusion of the backport and migrated release, and one unresolved
release with a request to verify the revision.

On the demonstrated Windows CPython target, run the same drill with the
local research wheel to exercise provider compatibility.

```sh
python -m tools.catalog.abc_upstream drill --wheel .abc/dist/python/abc_crypto_research-0.1.0-cp313-cp313-win_amd64.whl
```

The offline external consumer compares ABC's digest bytes against
`hashlib.sha256` for empty, binary, mutable, and strided byte input. It also
checks the replacement's streaming and ownership contract. Inspect the same
input and output format before switching providers in a supported release.
The rehearsal uses a simulated issue and a real local compatibility check.
