"""Build the native C++17 implementation and run independent SHA-512 comparisons."""

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
from time import perf_counter


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "sha512.cpp"
FLAGS = ["--driver-mode=g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]


def build_fixtures():
    known = [
        (b"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        (b"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),
        (b"a" * 1_000_000, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"),
    ]
    rng = random.Random(1804)
    sizes = [0, 1, 2, 31, 32, 110, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 257,
             383, 384, 511, 512, 1024, 4096, 65536]
    sizes.extend(rng.randrange(4097) for _ in range(128))
    variable = [rng.randbytes(size) for size in sizes]

    def lines(role, data, expected):
        return [role, data.hex(), expected, hashlib.sha512(data[:len(data) // 2]).hexdigest()]

    cases = [line for data, expected in known for line in lines("known-answer", data, expected)]
    cases.extend(line for data in variable for line in lines("comparison", data, hashlib.sha512(data).hexdigest()))
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
    with TemporaryDirectory(prefix="abc-sha512-cpp-") as directory:
        work = Path(directory)
        core = work / "sha512.o"
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
                               for file in ("sha512.cpp", "sha512.hpp", "tests.cpp")},
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
            baseline = []
            message = bytes((i * 73 + 11) & 0xFF for i in range(256)) * 4096
            for _ in range(4):
                hashlib.sha512(message).digest()
            for _ in range(len(samples)):
                start = perf_counter()
                for _ in range(16):
                    hashlib.sha512(message).digest()
                baseline.append(16 / (perf_counter() - start))
            report["benchmark"] = {"message_bytes": 1 << 20, "batches": len(samples), "hashes_per_batch": 16,
                                   "median_mib_s": statistics.median(samples), "samples_mib_s": samples,
                                   "oracle_median_mib_s": statistics.median(baseline),
                                   "oracle_samples_mib_s": baseline, "host_cpu": platform.processor()}
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--ubsan", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    options = parser.parse_args()
    print(json.dumps(check(options.coverage, options.ubsan, options.benchmark), indent=2))
