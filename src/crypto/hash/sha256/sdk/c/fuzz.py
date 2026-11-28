"""Run bounded libFuzzer input generation against the C ABI on the native host."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[6]
MANIFEST = ROOT / "src/crypto/hash/sha256/sdk/c/ffi/fuzz/Cargo.toml"
SEED = 83


def run(command):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=180, text=True,
                            encoding="utf-8", errors="replace", check=False)
    output = result.stdout + result.stderr
    print(output, flush=True)
    result.check_returncode()
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=10_000)
    args = parser.parse_args()
    if not 1 <= args.runs <= 100_000:
        parser.error("--runs must be between 1 and 100000")
    work_root = ROOT / ".abc/c-abi-fuzz"
    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="run-", dir=work_root) as temporary:
        work = Path(temporary)
        corpus = work / "corpus"
        corpus.mkdir()
        seeds = [bytes([0]), bytes([31, 0]), bytes([32]) + b"abc", bytes([40]) + bytes(range(136))]
        for number, seed in enumerate(seeds):
            (corpus / str(number)).write_bytes(seed)
        build = ["cargo", "+1.92.0", "rustc", "--locked", "--offline", "--release", "--manifest-path", MANIFEST,
                 "--target-dir", work / "target", "--bin", "sha256_abi"]
        if os.name == "nt":
            build.extend(["--", "-Clink-arg=/include:main"])
        run(build)
        executable = work / "target/release" / ("sha256_abi.exe" if os.name == "nt" else "sha256_abi")
        start = time.monotonic()
        output = run([executable, corpus, f"-runs={args.runs}", f"-seed={SEED}", "-max_len=1025", "-timeout=5",
                      "-rss_limit_mb=1024", "-print_final_stats=1", f"-artifact_prefix={work}{os.sep}"])
        if f"Done {args.runs} runs" not in output:
            raise RuntimeError("libFuzzer did not complete the requested run budget")
        report = {"inputs": args.runs, "seed": SEED, "corpus_sha256": [sha256(case).hexdigest() for case in seeds],
                  "coverage": "uninstrumented", "sanitizer": "none", "elapsed_ms": round((time.monotonic() - start) * 1000),
                  "oracle": "Same-core one-shot results and ABI boundary/lifecycle properties",
                  "harness_sha256": sha256((MANIFEST.parent / "fuzz_targets/sha256_abi.rs").read_bytes()).hexdigest(),
                  "ffi_sha256": sha256((MANIFEST.parent.parent / "src/lib.rs").read_bytes()).hexdigest()}
        encoded = json.dumps(report, indent=2) + "\n"
        if output_path := os.environ.get("ABC_TASK_OUTPUT"):
            (Path(output_path) / "fuzz-report.json").write_text(encoded, encoding="utf-8", newline="\n")
        print(encoded, flush=True)


if __name__ == "__main__":
    main()
