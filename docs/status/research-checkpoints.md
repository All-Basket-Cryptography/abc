# Reviewable local research runs

Define work with the existing module task contract. Give each task a fixed
program and argument list, owned or declared inputs, expected outputs, and
a timeout. Use task dependencies for the complete prerequisite closure.
Choose a planner target for a focused run.

```sh
python -m tools.abc_research propose --directory .abc/research/registry \
  --target repository-assurance:registry --max-attempts 2 --budget-seconds 240
```

The proposal contains the plan digest, selected tasks, task input
fingerprints, and resource limits. Inspect both the plan and proposal.
Each attempt reserves the sum of its task timeout limits. The budget counts
task seconds. Tool identification, verification, and filesystem overhead
fall outside that sum.

An independent reviewer signs the exact proposal under the research
namespace. Keep the private signer key on a separate trusted account.
Provision an operator-managed OpenSSH allowed-signers file and an
independent runner receipt key outside the checkout and checkpoint directory.
Use a trusted checkout and restrict access to the receipt key and checkpoint
storage. The local task runner runs trusted code under the caller's account.

```sh
ssh-keygen -Y sign -f /secure/reviewer-key -n abc-local-research .abc/research/registry/proposal.json
python -m tools.abc_research resume --directory .abc/research/registry \
  --signature .abc/research/registry/proposal.json.sig \
  --allowed-signers /secure/allowed_signers --reviewer reviewer \
  --receipt-key /secure/local-receipt-key
```

Each invocation verifies the independent approval, recomputes the plan and
fingerprints, and authenticates the checkpoint. An interrupted reservation
consumes one attempt. A subsequent invocation can reuse the ordinary
runner cache for authenticated, outputless tasks while budget remains.
Successful attempts use the same receipt verifier as the rest of ABC,
with an explicit target scope when the reviewer approved a partial plan.
The workflow produces local execution receipts. Production approval
requires the separately governed release process.

Exercise the full sequence with the independent signing and subprocess
fixtures. They cover actual retry, budget exhaustion, interrupted attempts,
stale source, a substituted plan, an unapproved reviewer, and altered
artifacts.

```sh
python -m unittest discover -s tests -p test_abc_research.py -v
```
