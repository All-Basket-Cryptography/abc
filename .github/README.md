# Pull request assurance

The first pull request starts from a base commit without ABC's assurance
engine. Its **Initial candidate fixtures (advisory)** job runs strict registry
validation and the candidate's standalone fixture suites. It runs on a hosted,
read-only `pull_request` job without persisted checkout credentials. The
separate `abc-required` check reports that the baseline awaits independent
review, including when the advisory job succeeds.

The repository owner establishes the first baseline through independent review
of the pinned workflow and assurance tools. Once that revision is on the base
branch, regular pull requests and merge queue checks run the planner from the
event's base commit. A fixed final job checks the complete task matrix and
receipt set. Changes to the workflow, planner, verifier, schemas, trust policy,
or module declarations require independent review. Candidate receipts stay in
the untrusted PR domain.

The **Rust-to-Lean research probe (advisory)** job uses a separate hosted runner
and pinned public toolchains. It runs the SHA-256 Lean specification checks and
the isolated Rust-to-Lean positive and negative fixtures. Its diagnostic
artifacts remain in the untrusted PR domain and do not feed `abc-required` or
production release evidence.

Run the local bootstrap fixtures and the reviewed-baseline gate fixture from
the repository root.

```sh
python -B -m unittest discover -s tests -p 'test_abc_ci_bootstrap.py' -v
python -B -m unittest discover -s tests -p 'test_abc_graph.py' -k ci_cli -v
```
