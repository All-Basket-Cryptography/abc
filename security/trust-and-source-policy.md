# ABC trust and source policy

## Proof claims

Every checked claim identifies its subject and source digests, exact theorem and preconditions, target, features, model, tools, allowed axioms, and limitations. The kernel-only profile audits the full transitive axiom closure against `assurance-policy.json`. This rejects `sorryAx`, any additional native evaluator axiom, and undeclared external axioms. A future native profile requires a separate policy revision and its own trust disclosure. Cryptographic assumptions belong in the theorem statement, with their defined scope.

An approved baseline supplies the expected theorem and specification. It re-extracts the model from fixed Rust input, audits model equivalence and external function semantics, and checks the theorem independently. The compiler, linker, runtime, FFI, and final binary require separate evidence. Functional refinement, memory safety, panic freedom, cryptographic security, and leakage are distinct claims.

## Sources and literature

Records identify original publication or repository, exact edition or revision, language, original license, and scope. Catalog-only records cite primary sources and can describe historical security status. Integrated upstream implementations have reproduction and patch tracking. ABC-maintained adaptations have first-party owners, original-language lineage, a modification log, and explicit support. Only import content with an applicable redistribution grant. Otherwise keep bibliographic data and links. Preserve notices and obtain separate review for ambiguous rights. The handoff’s proposed first-party license is pending confirmation by the repository owner.

## CI and evidence

Pull-request code, dependency generators, build scripts, and proof metaprograms are untrusted executables. Run them on ephemeral workers with minimum permissions and no production credentials. A privileged pull-request-target workflow must never execute candidate code. Reviewed baseline code independently selects and checks required work. Changes to that baseline or its policy require independent review. Use a fixed final job that fails on missing, cancelled, stale, or failed work. Pin Actions to immutable commits.

Untrusted PR, local, reviewed-main, and release are separate domains. An untrusted or local receipt cannot establish release approval. A local keyed receipt authenticates execution evidence only when the caller independently provisions the key and executes trusted local code. The runner does not sandbox code from files accessible by the same operating-system account. Keep local receipt keys outside the checkout and away from untrusted jobs. The gate recomputes expected subjects and fingerprints, and checks every attached output by digest. Release requires separately approved tools, reviewed sources, a fresh dependency-closure build, applicable proof and test evidence, and inspection of the exact artifact bytes.
