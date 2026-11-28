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

## JavaScript and TypeScript hashes

`node tools/benchmarks/javascript-hashes.mjs` checks the exact outputs
against Node's OpenSSL provider and measures one-shot hashes of 64 and
4,096 bytes. SHAKE256 emits 32 bytes. Each measurement takes the median
of nine 96-operation batches after 384 warm-up operations. The pipeline
includes input handling, initialization and output allocation.

On Windows x64 with an Intel Core i7-12700K, Node 24.12.0 and
OpenSSL 3.5.4, the 4,096-byte medians were as follows.

| Hash | JavaScript | TypeScript | Node/OpenSSL |
| --- | ---: | ---: | ---: |
| SHA-512 | 178.161 µs | 180.391 µs | 5.360 µs |
| SHA3-256 | 157.648 µs | 158.080 µs | 7.098 µs |
| SHAKE256 | 152.824 µs | 152.724 µs | 6.946 µs |
## Profile portfolio benchmark

The Node 24.12.0 benchmark runs one public workload for each of the 20
SDK profiles. It calls the JavaScript and TypeScript APIs and uses the
corresponding direct Node OpenSSL operation when the runtime exposes it.
For each workload, the runner compares the results before timing and
alternates method order across seven samples. It reports microseconds
per operation, the median and range, sample call counts, CPU and runtime.

```sh
npm ci --ignore-scripts --no-audit --prefix src/crypto/providers/ecmascript
node tools/benchmarks/portfolio.mjs
```

The benchmark uses public fixtures, including fixed post-quantum seeds.
It measures the selected one-shot workloads and runtime on one host.
The qualification evidence records the source, target and security scope.
[Qualification evidence](../../docs/plan/portfolio-verification.md)

## Paired SHA-3 and SHAKE measurements

Pass a baseline checkout or extract its hash source directories with
`git archive`. The script loads both versions in one Node process,
checks both against OpenSSL, and alternates their timing order across
11 samples. It records source digests, three input sizes and SHAKE
outputs that cover both short reads and multiple rate blocks.

```sh
node tools/benchmarks/keccak-ecmascript.mjs /absolute/path/to/baseline
```

## Paired SHA-256 and HMAC key-state measurements

Pass a baseline checkout or extract the six relevant source directories
from revision `50db178`. The runner compares both versions to Node
OpenSSL before collecting 11 alternating public-input timing samples.
The same-key case keeps a context per version across all samples. The
Node comparator creates a new HMAC for each message. The samples cover
both portable languages and include one-shot HMAC, SHA-256, four-block
HKDF, PBKDF2 and scrypt. These workloads use fixed test-only parameters.
The result includes source fingerprints, raw timings and runtime details.

```sh
git archive 50db178 src/crypto/hash/sha256 src/crypto/mac/hmac-sha256 \
  src/crypto/kdf/hkdf-sha256 src/crypto/kdf/pbkdf2-hmac-sha256 \
  src/crypto/kdf/scrypt src/crypto/inputs > baseline.tar
mkdir baseline
tar -xf baseline.tar -C baseline
node tools/benchmarks/hmac-prepared-ecmascript.mjs baseline
```

[Recorded Windows x64 comparison](../../docs/status/hmac-prepared-ecmascript-benchmark.json)

## Paired ChaCha20 and ChaCha20-Poly1305 measurements

The runner compares the two portable revisions and Node OpenSSL on public
67-, 1,024- and 16,387-byte messages. It checks each ciphertext and the
detached AEAD tag against OpenSSL before taking 11 alternating samples.
The standalone stream measurement includes restoring the caller buffer
before each in-place call. The AEAD cases use 27 bytes of associated data
and time the full `seal` API. The saved result includes source digests,
batch counts, nominal host details and raw timings.

```sh
git archive 1d07956 src/crypto/cipher/chacha20 src/crypto/mac/poly1305 \
  src/crypto/aead/chacha20-poly1305 src/crypto/inputs > baseline.tar
mkdir baseline
tar -xf baseline.tar -C baseline
node tools/benchmarks/chacha20-ecmascript.mjs baseline
```

[Recorded Windows x64 comparison](../../docs/status/chacha20-word-output-benchmark.json)

## Paired Poly1305 measurements

The ECMAScript runner compares standalone tags with an independent
arbitrary-precision formula and AEAD seal outputs with Node OpenSSL.
The two revisions alternate across 11 samples over public 0-, 17-,
1,024- and 16,387-byte payloads. Each call includes setup and tag
calculation. AEAD uses 27 bytes of associated data. Results record raw
samples and source fingerprints.

```sh
mkdir -p .abc/poly-baseline
git archive --output=.abc/poly-baseline.tar d1b008c src/crypto/cipher/chacha20 \
  src/crypto/mac/poly1305 src/crypto/aead/chacha20-poly1305 src/crypto/inputs
tar -xf .abc/poly-baseline.tar -C .abc/poly-baseline
node tools/benchmarks/poly1305-ecmascript.mjs .abc/poly-baseline
```

The C++ fixture links both versions into one executable. In a Windows
x64 Visual Studio developer shell with Clang 21.1.8, prepare a scratch
directory with `paired.cpp` from [the benchmark fixture](poly1305-paired.cpp).
Copy `poly1305.cpp` and `poly1305.hpp` from
`src/crypto/mac/poly1305/impl/cpp` at `d1b008c` into a `baseline`
subdirectory. Copy the working versions into `columns`.

```sh
clang++ -std=c++17 -O2 -Wall -Wextra -Werror -Dnative_poly1305=native_poly1305_baseline -c baseline/poly1305.cpp -o baseline.obj
clang++ -std=c++17 -O2 -Wall -Wextra -Werror -c columns/poly1305.cpp -o columns.obj
clang++ -std=c++17 -O2 -Wall -Wextra -Werror -fuse-ld=lld paired.cpp baseline.obj columns.obj -o paired.exe
./paired.exe
```

Each row has input size, the two medians in nanoseconds, and the median,
minimum and maximum of the baseline-to-candidate ratios across nine
alternating batches. The fixture checks both implementations on 16 view
offsets for each message size.
[ECMAScript evidence](../../docs/status/poly1305-window-benchmark.json) · [C++ evidence](../../docs/status/poly1305-cpp-benchmark.json)
