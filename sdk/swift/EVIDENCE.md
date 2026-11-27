# Swift SHA-256 research evidence

On 2026-11-28 at 01:52 Asia/Taipei, GitHub Actions built a SwiftPM package and
ran the separate consumer against the unpacked archive. The job used macOS
15.8.2 arm64, runner image `macos-15-arm64` version `20261123.0558.1`, Apple
Swift 6.1.2, and Rust 1.92.0 for `aarch64-apple-darwin`. The checked-out PR
merge commit was `c8792b718d63408c1ae9ac75141215d7d0ac30cf`, based on PR head
`e4a5d232bf35f57c812b6192821fb4029fbe2298`.
[GitHub Actions run](https://github.com/All-Basket-Cryptography/abc/actions/runs/46045037458)
[Consumer job](https://github.com/All-Basket-Cryptography/abc/actions/runs/46045037458/job/140662050455)

```sh
python -B sdk/swift/package.py --consumer --output dist/swift
```

The job reported `Swift SHA-256 external consumer passed`. The consumer
checked the NIST `abc` digest, implementation identity, split updates, reset,
repeated finalization, and closed-handle errors. The archive digest was
recorded in the job log.

The workflow now attaches the tested ZIP and its `swift-artifacts.json`
conformance report to successful runs for seven days.

| Artifact | SHA-256 |
| --- | --- |
| `abc-swift-0.1.0-aarch64-apple-darwin.zip` | `96ba52e82103fce1d83ecdc0879eb85c2c7707745d8abb0d795f92b1d2a71585` |

This evidence covers macOS on Apple silicon. iOS device, simulator, and
XCFramework verification remain open.
