# ABC Agent Engineering Instructions

This file is an implementation-agent handoff template, not evidence that ABC has been implemented. Merge it with existing repository instructions; do not overwrite existing policies or bypass higher-priority user or environment instructions.

## Mission and scope

Implement All-Basket Cryptography as one first-party monorepo covering the historical and contemporary cryptographic catalog, original-language implementations, Lean specifications and implementation-specific proof evidence, fuzzing, documentation, literature, modular verification, maintenance, and installable SDKs.

Required SDK ecosystems: Rust, C, C++, Go, Java, JavaScript/TypeScript on npm, and Python on PyPI. Planned extensions: Swift, Kotlin/Android, .NET, WASI, and appropriate embedded targets. Do not silently reduce this scope to Rust plus wrappers with no deliverable roadmap.

Read `ABC-MASTER-PLAN.zh-Hant.md`, `TASKS.json`, and this file before implementation. If the handoff was copied under `docs/plan/`, resolve these paths there. The master plan defines engineering requirements; task dependencies define scheduling. Record subsequent authorized requirement changes explicitly.

## Work autonomously and preserve the workspace

- Inspect existing repository state, instructions, licenses, and uncommitted work first. Preserve unrelated work.
- Perform authorized reversible local implementation, building, testing, packaging, and documentation without repeatedly asking for approval.
- This handoff alone does not authorize public publication, purchases, external messages, or security disclosures. Follow the actual authorization in the implementation session. Complete local preparation and reviewable artifacts before any final approval step that is actually required.
- If access or a tool is blocked, retain the exact error and a minimal reproduction, mark the affected task blocked, and continue independent work. Never bypass access controls.
- Use English in source code, comments, identifiers, public repository documentation, and API examples unless the user directs otherwise. User-facing progress may be Traditional Chinese.

## Start with working vertical slices

Complete M0 and M1 first, then continue into M2. Do not stop at a new plan, an empty directory tree, placeholder packages, or mock verifier outputs.

Prove and test a small isolated engineering probe to validate the toolchain. It is not a production cryptographic primitive and cannot replace the SHA-256 milestone.

Pin an actually tested Rust/Charon/Aeneas/Lean/Mathlib combination. Never invent a compatible version, commit, successful command, benchmark, audit, or external reviewer.

## Data and module boundaries

- Keep canonical registry identity and descriptive data in one location. Derive indexes, website data, capabilities, and release summaries.
- Track algorithm, specification, implementation, binding, build target, evidence, and release artifact separately.
- Preserve original upstream language, revision, license, and modification history. A verified Rust rewrite does not verify the original C implementation.
- Give each source file an owner and capture implicit build, generation, tooling, policy, test-vector, and dispatch inputs.
- Keep large binaries, proof caches, raw traces, and large corpora out of ordinary Git. Store their hashes, provenance, and reproduction instructions in the monorepo.

## Formal verification integrity

- State each theorem, precondition, scope, source specification, source revision, target, and trusted computing base precisely.
- Never weaken an intended theorem, redefine the specification as the implementation, add an impossible precondition, or change generated semantics just to pass.
- Reject direct and transitive `sorryAx` and unapproved axioms in accepted proof claims. Audit dependency closure, not just source text.
- Use a versioned standard-axiom allowlist. Record cryptographic assumptions as explicit hypotheses where possible.
- Native evaluation has a distinct trust profile. Audit actual axiom dependencies for the pinned Lean version instead of relying on tactic names alone.
- Re-extract generated models and compare them. Any transformation must be versioned, reproducible, and reviewed.
- Use trusted expected theorem definitions and independent rechecking/comparison for unreviewed agent or contributor proofs. Do not trust their self-reported success logs.
- Functional correctness, cryptographic security, memory safety, panic freedom, constant time, compiler correctness, and binary correspondence are separate claims.
- Unsupported language features or proof routes remain blocked or partial. Existing F*/Rocq evidence must not be relabeled as Lean evidence without a checked connection.

## Incremental execution

- The knowledge/evidence graphs may have cycles. Only the executable task graph must be a DAG.
- Use `consumer -> prerequisite` dependency direction and reverse traversal for impact.
- Analyze both base and head graphs for additions, removals, renames, changed edges, and features. Their union is for impact analysis only; execute the surviving head task DAG.
- Start at real module/import granularity. Do not promise unsound theorem-level dependency inference.
- Unknown files, missing base, invalid references, and unresolved inputs must cause conservative execution or a clear failure, never a silent empty plan.
- Emit a plan with reasons, fingerprints, expected tasks, and fallback decisions. Always run a stable final status gate.
- Changes to planner, verifier, aggregator, or trust rules require trusted baseline checks, independent candidate fixtures, and independent review. A candidate tool cannot approve a weakened version of its own gate.

## Evidence and CI trust

- Cache keys include source and transitive inputs, tools, configuration, targets, features, policy, and trust domain.
- A cache is an optimization, not proof evidence. PR outputs cannot be promoted directly to release evidence.
- Isolate untrusted PR code, Lean metaprograms, build scripts, and generators from release credentials and privileged infrastructure.
- Pin third-party actions to reviewed full commit SHAs. Do not interpolate untrusted strings into shell code.
- Do not run untrusted PR code in privileged `pull_request_target` workflows.
- Missing, cancelled, failed, unexecuted, stale, or mismatched required work cannot pass the final gate.
- Build release evidence from reviewed source and approved tools, and publish only the reviewed artifact bytes.

## Testing and SDK delivery

- Use source-traceable vectors, properties, boundaries, stateful fuzzing, and genuinely independent differential oracles.
- If no independent oracle exists, record `blocked` with reason `missing_oracle`. Never copy the same implementation and call it independent.
- Record real fuzz time, inputs, corpus, oracle, coverage type, errors, OOM, and timeouts. No-crash is not proof of safety.
- Check the fuzz harness itself for input sensitivity and swallowed failures.
- Test each core, binding, and built target at its own boundary. Wrappers around one core are not independent oracles.
- Install SDK artifacts in clean external consumer projects. Workspace-only examples, generated wrappers, and empty packages are not completed SDKs.
- Make actual provider/implementation/dispatch identity observable. No silent downgrade to a different assurance profile.
- Declare pointer/ownership obligations for C ABI. Never promise arbitrary invalid-pointer safety.
- RNG failure must fail. Test seeds must not leak into production behavior. Nonce ownership and key-usage limits belong in API contracts.

## Maintenance and release claims

- Distinguish catalog-only, integrated-upstream, and ABC-maintained modules.
- Publish exact support scope and EOL policies that real maintainers can fulfill. Do not invent five-year LTS or round-the-clock guarantees.
- Preserve compatibility where possible; security-required breaking changes need explicit migration and regression evidence.
- Never globally ignore vulnerabilities merely to obtain green CI. Exceptions require scope, owner, justification, and expiry.
- Production use is a versioned policy decision based on actual evidence, maintenance, appropriate review, and target-specific requirements. No AI self-awarded industry certification.
- Commercial ISO/certification consulting is outside ABC's codebase and governance scope.

## Completion and handoff

Update task state, evidence references, blockers, ADRs, and `docs/status/progress.md` after meaningful batches. A task can be done only when its acceptance criteria have evidence.

Report actual commands and results, not intended ones. Separate implementation completed, proof completed, tests executed, artifacts packaged, external review pending, and publication pending.

Keep first-class negative tests for stale proofs, hidden axioms, missing graph edges, forged evidence, toolchain mismatch, contaminated cache, invalid packages, unsafe fallback, and removed required jobs.
