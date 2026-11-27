# Node uses the research WASM provider

The npm research package selects WASM in Node and reports `sha256-abc-rust-portable` and `wasm32-unknown-unknown`. A single package provides the same API and binary to Node and browser consumers. The current Node requirements are byte input, one-shot hashing, streaming, and explicit context lifetime. An additional native backend would require a concrete workload, separate target evidence, and an observable selection policy.

Run `python abc.py consumer-test --sdk npm --artifact dist/conformance/abc-cryptography-research-0.1.0.tgz --node-benchmark` to repeat the comparison. Node 24.12.0 on Windows x64 reported 3.052 ms WASM initialization. Five warmed samples per workload produced the following medians. Node's built-in OpenSSL 3.5.4 API is a reference baseline.

| Input | Batch | WASM | Node OpenSSL |
| --- | ---: | ---: | ---: |
| 32 bytes | 5,000 digests | 3.458 ms | 6.395 ms |
| 4 KiB | 2,000 digests | 31.434 ms | 5.626 ms |
| 1 MiB | 12 digests | 47.422 ms | 5.575 ms |

This session sampled one development host. The large-input results identify a workload where native throughput could justify a separate provider. Node passed package loading and input and lifetime checks. Browser verification awaits a compatible test runner.
