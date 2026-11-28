# Pull request assurance

The first pull request starts from a base commit without ABC's assurance
engine. Its **Initial candidate fixtures (advisory)** job runs strict registry
validation and the candidate's standalone fixture suites. It runs on a hosted,
read-only `pull_request` job without persisted checkout credentials. It also
rehearses planning, task execution and receipt aggregation against the exact
candidate revision. This rehearsal is advisory and stays in the untrusted PR
domain. The `abc-bootstrap-rehearsal` artifact contains its plan and receipts.
The separate `abc-required` check reports that the base awaits
independent review, including when the rehearsal succeeds.

## First baseline

1. Review the exact first PR head. The review covers the workflow pins,
   planner and runner, verifier, policy and schemas, task manifests, and the
   candidate and hosted proof evidence relied on by the initial baseline.
   Record approval on that revision from a reviewer independent of its author.
2. The repository owner incorporates the reviewed first revision into `main`.
   The repository owner's action establishes the trust anchor for the first
   baseline, independently of the advisory result. Later revisions containing
   an assurance change also require independent review.
3. Check the resulting `abc-main-baseline` run on the exact new `main` commit.
   The runner plans with that commit as both base and head, runs the required
   metadata tasks, and verifies their receipts. This check has a distinct name
   so it cannot satisfy a pull request's `abc-required` gate.

Regular pull requests and merge queue checks run the planner from the event's
base revision. The `abc-required` job checks the complete planned matrix and
receipt set. Changes to protected assurance inputs cannot use this ordinary
candidate path. Install those revisions as a separately reviewed baseline
with the approval recorded for the exact revision. [Trust and source policy](../docs/security/trust-and-source-policy.md)

## Main diagnostics

The main diagnostics and PR workers run the bounded-add and SHA-256 native
fuzz tasks on separate Windows x64 workers with pinned tools and lockfiles.
The native harness retains all corpus seeds without coverage instrumentation.
The pinned libFuzzer on Ubuntu asserted while choosing its first mutation of
this corpus. [Linux engine logs](https://github.com/All-Basket-Cryptography/abc/actions/runs/46119615418)

The main workflow reuses the provisioned Linux SHA-256 and Poly1305 Lean
source replays. Fuzz and formal artifacts retain the scope stated by their
generators. The full
graph also contains Windows, macOS and provider-specific tasks. Use the
reported task target and tool requirements to replay those tasks on the
appropriate hosts. The graph and the runner remain available for those
checks independently of what is installed on the hosted Ubuntu workers.

```sh
python -B -m tools.abc_cli plan --head HEAD --output .abc/plan.json
python -B -m tools.abc_cli run --plan .abc/plan.json \
  --target sha256:differential-fuzz --output .abc/sha256-diagnostics
```

The **Rust-to-Lean research probe (advisory)** job uses a separate hosted runner
and pinned public toolchains. It runs the SHA-256 Lean specification checks and
the isolated Rust-to-Lean positive and negative fixtures. Its diagnostic
artifacts remain in the untrusted PR domain and do not feed `abc-required` or
production release evidence.

Run the local bootstrap fixtures and the reviewed-baseline gate fixture from
the repository root.

```sh
python -B -m unittest discover -s tools/tests -p 'test_abc_ci_bootstrap.py' -v
python -B -m unittest discover -s tools/tests -p 'test_abc_graph.py' -k ci_cli -v
```

To rehearse the actual baseline in a clean checkout, pass its full commit
ID for both revision arguments. The command verifies the same receipt closure
and returns `advisory-passed`; the repository's review establishes trust.

```sh
revision=$(git rev-parse HEAD)
python -B -m tools.verification.abc_ci baseline-smoke --repo . \
  --base "$revision" --head "$revision" --directory .abc/baseline-smoke
```
