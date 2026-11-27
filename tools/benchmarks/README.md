# Public-input SHA-256 benchmark

Run from the repository root with Node.js, Rust 1.92.0, and the native linker available. On Windows use the Visual Studio x64 developer environment.

```sh
node tools/benchmarks/run.mjs
```

The Rust benchmark measures the portable one-shot SHA-256 API at lengths 0, 55, 56, 63, 64, 65, 1,024, 16,384, and 1,048,576 bytes. It reserves a pool of eight precomputed public messages per length, warms each size for three batches, and observes fifteen batches per size in rotating order. Allocation, generation, and terminal output happen outside each measured batch. Loop and API overhead are part of the timing, and the inputs are reused after warmup. Rust's `black_box` keeps inputs and results observable to the compiler on a best-effort basis. [Rust 1.92.0 `black_box`](https://doc.rust-lang.org/1.92.0/std/hint/fn.black_box.html)

The Node.js driver verifies the size/round matrix and reports median time per operation, observed min and max, effective payload throughput for nonempty inputs, and a percentile-bootstrap interval over the per-batch medians. The calculation resamples fifteen batches 2,000 times and uses the 2.5th and 97.5th percentiles. The interval describes within-run sampling variation under an independence assumption. CPU frequency changes, correlated scheduler noise, and other systematic effects can be larger. For zero-byte messages use time per operation.

The result, build command, compiler version, measurement log, binary digest, and relevant source digests are saved under a fresh `.abc/benchmarks/` directory. `result.schema.json` describes the record. The result includes aggregate active CPU time from OS counters across the whole benchmark. This is an environment context measure and includes the benchmark's own work. Reported MHz is the OS-advertised value. Affinity is inherited, and temperatures, clock throttling, and per-request scheduling were unmeasured.

## Regression reproduction

1. Use the same host, OS build, target, linker, compiler, power policy, and benchmark revision for baseline and candidate. Keep the actual result records, including the measured source and executable digests.
2. Compare the same message lengths and batch parameters. Compare medians and their intervals, and inspect raw batch times and CPU utilization before interpreting a change. Repeat baseline and candidate in alternating order if the result affects a decision.
3. Use shared CI measurements as coarse regression signals. Use repeated measurements on a controlled host before changing platform support or claiming an optimized path is faster. Keep target dispatch, portability, and maintenance costs in the optimization decision.

## Timing and leakage evidence

**Public-input profile.** The benchmark fixes a public provider and message length per sample. It measures execution time and throughput. The size-dependent behavior of public inputs is allowed by this profile.

**Secret-bearing profile.** For each candidate algorithm, declare secret and public inputs, including key material, intermediate key-dependent state, message contents, lengths, nonces, status, dispatch, and the outputs explicitly allowed to be released. Define a leakage model over branch decisions, accessed addresses or cache lines, and target instructions with data-dependent latency. State modeled CPU and compiler behaviors and any remaining hardware or runtime assumptions. The expected property compares two executions with the same public inputs and different secret inputs, with equality of the modeled observations before any allowed release.

For a secret-bearing optimized path, require a target-specific source/model review, explicit compiler and feature pins, and inspection or analyzed evidence for the actual emitted code and dispatch closure. Record trust boundaries for assembly, FFI, external models, and target-specific dependencies. Require review of every eligible hardware and portable fallback path under its own profile. Where the model omits effects such as speculation, shared cache contention, power, interrupts, or allocator activity, retain that scope in the evidence and policy decision.

A timing test complements that analysis. Use generated test-only input classes with the same public parameters. Fix the measurement environment, warmup, sample budget, interleaving, and statistical decision rule before collecting data. Randomize the order of classes, validate the harness on controls, and record raw run metadata, sample counts, CPU and OS state, and uncertainty. A Welch two-sample test can flag differences in mean time under the selected setup. Shared CI timings are coarse diagnostics. The public-input benchmark supplies no timing-validation evidence for HMAC, HKDF, keys, or optimized implementations. [Dudect methodology](https://eprint.iacr.org/2016/1123)
