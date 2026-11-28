# Dependency graphs and impact planner

`module.toml` declares repository-relative file and directory ownership. The
most specific owner wins when parent directories contain child modules.
Duplicate declarations, missing inputs, invalid references, and executable
dependency cycles fail validation. `shared_inputs` captures inputs from other
owners. Each task declares its program and arguments, task prerequisites,
target, features, tool names, and optional extra inputs and outputs.
`always = true` keeps the required metadata and status checks in every plan.

The Cargo adapter uses checked-in manifest and lock inputs. It follows local
normal, build, dev, target-specific, and inherited path dependencies. It
conservatively retains optional and target-specific edges across all supported
configurations. Build scripts, code generators, and native SDK dependencies
outside Cargo must declare additional inputs and edges. The Lean adapter reads
actual import headers, associates local names with declared Lean source roots,
and tracks lock or generator inputs declared for external and generated
imports. An unclassified import widens the plan and records why.

Catalog links and evidence-subject links are projections of the registry.
Execution ordering uses the checked-in task prerequisites. During impact
analysis, reverse module and task edges from both snapshots preserve the effect
of removals and ownership changes. Only the head task graph is scheduled. A
removed module requires a surviving compatibility task. Documentation changes
select metadata and documentation tasks and any task that explicitly depends on
the changed file. A missing base or unowned changed path widens verification.

```sh
python -m unittest discover -s tests -p 'test_abc_graph.py' -v
python -m tools.abc_cli graph build --revision WORKTREE
python -m tools.abc_cli plan --base BASE --head HEAD --merge-base --output .abc/plan.json
```

Tests use temporary Git repositories and cover dependency paths, aliases,
scope changes, doc isolation, fallback, target-specific dependencies, actual
Lean import headers, ownership transfer, task cycles, and a refactoring where
the combined old and new edges form a cycle. A repository snapshot fixture
also verifies SHA-256 and SHA3-256 leaf isolation against the actual Cargo
graph. Both specification modules import a shared Lean byte-encoding module.
The repository fixture changes that module and checks that both Lean tasks
are selected. Running the Lean tasks requires their pinned toolchain.

The CI fixture runs the baseline plan, worker, and final gate commands against
normal source changes in an isolated committed repository. Its negative case
removes one required worker receipt and observes a gate failure.
