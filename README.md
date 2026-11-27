# All-Basket Cryptography

ABC is a research monorepo for a source-traceable cryptography catalog, portable implementations, SDKs, and verification evidence. The [master plan](docs/plan/abc/ABC-MASTER-PLAN.zh-Hant.md) defines the full scope. [Progress](docs/status/progress.md) records the implemented slices and blockers.

Use Python 3.12 or newer and Git for the repository tools. Cargo 1.92.0 builds the research SHA-256 core. The npm package also needs Node, npm, and the `wasm32-unknown-unknown` target for this Rust release.

```text
python abc.py doctor --json
python abc.py registry validate --strict
python abc.py status
python abc.py plan --head WORKTREE --output .abc/plan.json
python abc.py run --plan .abc/plan.json --output .abc/run
python abc.py docs build
cargo +1.92.0 test --workspace --locked --offline
```

Use a fresh run output directory for each evidence run. `WORKTREE` supports local development before the initial Git revision. To check a committed change, run from a clean checkout and specify `--base BASE --head HEAD --merge-base`. A plan with no usable base schedules the full required scope.

Run the Windows full plan from a Visual Studio x64 developer shell for native fuzzing and benchmarks. If the Cargo home is read-only, set `CARGO_HOME` to a writable location populated with the dependencies in the fuzz lockfiles. Set `ABC_JAVA_HOME` to a JDK 17 installation for the Java checks. The full gate remains unsuccessful while required formal tools are unavailable.

```text
python abc.py package --sdk rust --output dist
python abc.py consumer-test --sdk rust --artifact dist/abc-sha256-0.1.0.crate
python abc.py package --sdk npm --output dist
python abc.py consumer-test --sdk npm --artifact dist/abc-cryptography-research-0.1.0.tgz
```

Pass `--browser` with a Chromium executable to extend the npm consumer check to a browser. SDK packaging and consumer results are research evidence. The [assurance policy](security/trust-and-source-policy.md) governs formal and release claims.

On Windows amd64, `python abc.py conformance --output dist/conformance` builds and runs all seven research consumers. Set `ABC_JAVA_HOME` to a JDK 17 directory for the JNI package. Use a fresh output directory for each run. See the [acceptance review](docs/status/acceptance.md) for current coverage and blockers.

`python abc.py release prepare --profile research --output dist/research` creates the Rust and npm research release set, SBOM, and provenance. `python abc.py release verify --manifest dist/research/release-set.json` independently rebuilds and compares the packaged bytes.
