"""Build the native C++17 implementation and run independent SHA-256 comparisons."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import ssl
import statistics
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "sha256.cpp"
FLAGS = ["--driver-mode=g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]


def build_fixtures():
    vectors = json.loads((HERE.parents[1] / "spec/vectors.json").read_text(encoding="utf-8"))["vectors"]
    known = [(bytes.fromhex(v["input_hex"]), v["output_hex"]) for v in vectors]
    known.extend([
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        (b"a" * 1_000_000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
    ])
    rng = random.Random(1804)
    sizes = [0, 1, 2, 31, 32, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129,
             255, 256, 257, 511, 512, 1024, 4096, 65536]
    sizes.extend(rng.randrange(4097) for _ in range(128))
    variable = [rng.randbytes(size) for size in sizes]

    def lines(role, data, expected):
        return [role, data.hex(), expected, hashlib.sha256(data[:len(data) // 2]).hexdigest()]

    cases = [line for data, expected in known for line in lines("known-answer", data, expected)]
    cases.extend(line for data in variable for line in lines("comparison", data, hashlib.sha256(data).hexdigest()))
    return "\n".join(cases) + "\n"


def run(args, **kwargs):
    result = subprocess.run(args, text=True, encoding="utf-8", capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def check(coverage, ubsan, benchmark):
    if (coverage or ubsan) and benchmark:
        raise ValueError("Benchmark the uninstrumented build separately")
    compiler = run(["clang", "--version"]).splitlines()
    flags = FLAGS.copy()
    if coverage:
        flags.extend(["-fprofile-instr-generate", "-fcoverage-mapping"])
    if ubsan:
        flags.extend(["-fsanitize=undefined", "-fno-sanitize-recover=undefined"])
    with TemporaryDirectory(prefix="abc-sha256-cpp-") as directory:
        work = Path(directory)
        core = work / "sha256.o"
        consumer = work / ("checks.exe" if os.name == "nt" else "checks")
        run(["clang", *flags, "-c", str(SOURCE), "-o", str(core)])
        run(["clang", *flags, str(HERE / "tests.cpp"), str(core), "-o", str(consumer)])
        raw = work / "source.profraw"
        env = {**os.environ, "LLVM_PROFILE_FILE": str(raw)}
        results = json.loads(run([str(consumer)], input=build_fixtures(), env=env))
        report = {
            "status": "passed",
            "compiler": compiler[:2],
            "flags": flags,
            "target": platform.machine(),
            "oracle": ssl.OPENSSL_VERSION + " via Python hashlib",
            "sources_sha256": {file: hashlib.sha256((HERE / file).read_bytes()).hexdigest()
                               for file in ("sha256.cpp", "sha256.hpp", "tests.cpp")},
            "results": results,
        }
        if coverage:
            merged = work / "source.profdata"
            run(["llvm-profdata", "merge", "-sparse", str(raw), "-o", str(merged)])
            data = json.loads(run(["llvm-cov", "export", "--summary-only", f"--instr-profile={merged}",
                                   str(consumer), str(SOURCE)]))
            report["llvm_source_coverage"] = data["data"][0]["files"][0]["summary"]
        if benchmark:
            samples = json.loads(run([str(consumer), "--benchmark"]))
            report["benchmark"] = {"message_bytes": 1 << 20, "batches": len(samples), "hashes_per_batch": 16,
                                   "median_mib_s": statistics.median(samples), "samples_mib_s": samples,
                                   "host_cpu": platform.processor()}
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--ubsan", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    options = parser.parse_args()
    print(json.dumps(check(options.coverage, options.ubsan, options.benchmark), indent=2))
