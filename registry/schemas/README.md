# ABC metadata contracts

`registry.schema.json` is a Draft 2020-12 schema for individual canonical records. `module.schema.json` describes the data model decoded from each `module.toml`. Module manifests own executable tasks and source ownership. They stay outside the identity registry.

The offline Python validator checks the Draft 2020-12 vocabulary used by these schemas, then applies ABC-specific constraints on typed references, evidence states, provenance, ownership, and repository paths. It rejects duplicate keys before applying schema rules. Schema references resolve locally. Document-supplied schema declarations and remote references are unsupported.

Version 1 is the first supported format. Unknown record fields and versions fail validation. Any future schema extension or migration must land with an explicit version and examples before a record can use it. Alias and tombstone records preserve prior identifiers. A retired or aliased identifier remains unavailable for reuse.

Run the registry contract fixtures from the repository root with `python -m unittest discover -s tools/tests/fixtures/registry -p test_registry.py`.
