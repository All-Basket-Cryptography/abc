"""Package and exercise the WASI Preview 2 research component."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[6]
TARGET = "wasm32-wasip2"
WASMTIME_VERSION = "50.0.3"


def call(argv, input_bytes=None):
    result = subprocess.run(argv, cwd=ROOT, input=input_bytes, capture_output=True, timeout=150)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.stdout.decode().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wasmtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    wasmtime = args.wasmtime.resolve(strict=True)
    version = call([wasmtime, "--version"])
    if version.split()[:2] != ["wasmtime", WASMTIME_VERSION]:
        raise ValueError(f"Expected Wasmtime {WASMTIME_VERSION}, got {version}")
    args.output.mkdir(parents=True, exist_ok=True)
    artifact = args.output.resolve() / "abc-sha256-0.1.0-wasm32-wasip2.wasm"
    with TemporaryDirectory(prefix="abc-wasip2-") as stage:
        target_dir = Path(stage)
        call(["cargo", "+1.92.0", "build", "--manifest-path", ROOT / "tools/build/rust/Cargo.toml", "--release", "--locked", "--offline", "--target", TARGET,
              "--target-dir", target_dir, "-p", "abc-wasi-sha256"])
        shutil.copyfile(target_dir / TARGET / "release/abc-wasi-sha256.wasm", artifact)
    command = [wasmtime, "run", artifact]
    if call([*command, "--identity"]) != "sha256-abc-rust-portable":
        raise ValueError("Unexpected component implementation identity")
    vectors = [b"", b"abc", *(bytes(index % 251 for index in range(size)) for size in (55, 56, 63, 64, 65, 19_000))]
    for data in vectors:
        if call(command, data) != hashlib.sha256(data).hexdigest():
            raise ValueError(f"WASI SHA-256 mismatch at {len(data)} bytes")
    report = {"profile": "research", "target": TARGET, "wasmtime": version, "artifact": artifact.name,
              "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "vectors_passed": len(vectors)}
    (args.output / "wasi-conformance.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
