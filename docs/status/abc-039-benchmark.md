# ABC-039 benchmark and leakage methodology

The public-input SHA-256 benchmark ran locally on 2026-11-28 at 01:06 Asia/Taipei. The result covers the one-shot portable Rust API on a 12th Gen Intel Core i7-12700K with 20 logical CPUs and Windows 11 build 26200. The OS reported 3,610 MHz and the Balanced power policy. Aggregate CPU utilization was 19.1% during the run. The host was shared, with inherited CPU affinity and no temperature or clock-throttling measurements.

Rust and Cargo 1.92.0 targeted `x86_64-pc-windows-msvc` with LLVM 21.1.3 and MSVC linker 14.44.35222.0. The benchmark used `-Ctarget-cpu=generic`, release optimization level 3, one codegen unit, and no LTO. The Rust driver measured fifteen batches per length after three warmup batches. Eight deterministic public messages per length were allocated before measurement. The intervals below are within-run 95% percentile-bootstrap estimates.

| Message bytes | Median time per call | 95% interval | Median throughput |
|---:|---:|---:|---:|
| 0 | 192.68 ns | 191.37–193.02 ns | — |
| 55 | 192.77 ns | 192.04–193.48 ns | 272.10 MiB/s |
| 56 | 370.20 ns | 368.84–373.44 ns | 144.26 MiB/s |
| 63 | 369.67 ns | 368.70–371.27 ns | 162.53 MiB/s |
| 64 | 365.46 ns | 363.64–365.95 ns | 167.01 MiB/s |
| 65 | 365.23 ns | 364.25–366.90 ns | 169.73 MiB/s |
| 1,024 | 2.992 µs | 2.972–3.052 µs | 326.34 MiB/s |
| 16,384 | 45.548 µs | 45.309–46.041 µs | 343.04 MiB/s |
| 1,048,576 | 2.986 ms | 2.961–2.991 ms | 334.85 MiB/s |

`node tools/benchmarks/run.mjs` exited 0. PowerShell `Test-Json` validated `.abc/benchmarks/run-5erl4U/result.json` against `tools/benchmarks/result.schema.json`. The result SHA-256 is `4a83fdf20b54ea44a3952fb955036c23ed6ec642039a4f076dc84979cc2e5750` and the measured binary SHA-256 is `1a6eca54ecec3f6f131dc9b31f1b2a95c8af9dbe9fbdf15ca486f018423eba68`. The adjacent logs contain the raw samples and exact build command. The task graph built with zero diagnostics and recorded the benchmark dependency on `sha256`.

`tools/benchmarks/README.md` records the public-input measurement protocol, regression reproduction, and evidence required by a secret-bearing profile. The current run supplies throughput and latency observations for a public-input workload on this host. Secret-class timing and target-specific leakage analysis remain unexecuted.
