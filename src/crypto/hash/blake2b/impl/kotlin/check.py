"""Verify a separately compiled Kotlin BLAKE2b JAR with independent fixtures."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
from statistics import median
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "src/Blake2b.kt"
CONSUMER = HERE / "tests/Blake2bChecks.kt"
MAIN = "org.allbasket.abc.hash.blake2b.kotlin.Blake2bChecksKt"
REFERENCE = runpy.run_path(str(HERE.parent / "cpp" / "check.py"))


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=90, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout.strip(), result.stderr.strip()


def benchmark(command):
    native = [float(sample) for sample in run([*command, "--benchmark"])[0].split(",")]
    message = bytes((37 * i + 11) & 0xff for i in range(256)) * 4096
    for _ in range(4):
        REFERENCE["reference"](message, 64)
    openssl = []
    for _ in native:
        start = perf_counter()
        for _ in range(16):
            REFERENCE["reference"](message, 64)
        openssl.append(16 / (perf_counter() - start))
    return {"message_bytes": len(message), "hashes_per_batch": 16, "native_median_mib_s": median(native),
            "openssl_median_mib_s": median(openssl)}


def check(jdk, kotlin, measured):
    name = "java.exe" if os.name == "nt" else "java"
    java = str(jdk.resolve() / "bin" / name) if jdk else name
    runtime = "\n".join(run([java, "-version"])).strip()
    if not re.search(r'version "17(?:\.|\")', runtime):
        raise ValueError("The qualification run requires JDK 17")
    distribution = kotlin.resolve()
    lib = distribution / "lib"
    stdlib = lib / "kotlin-stdlib.jar"
    compiler = [java, f"-Dkotlin.home={distribution}", "-cp", str(lib / "*"),
                "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
    version = "\n".join(run([*compiler, "-version"])).strip()
    if not re.search(r"\bkotlinc-jvm 2\.1\.21\b", version):
        raise ValueError(f"Expected Kotlin 2.1.21, got {version}")
    flags = ["-Xjdk-release=17", "-Werror", "-no-stdlib", "-no-reflect"]

    with TemporaryDirectory(prefix="abc-blake2b-kotlin-") as directory:
        work = Path(directory)
        artifact, consumer = work / "abc-blake2b-kotlin.jar", work / "consumer.jar"
        run([*compiler, *flags, "-classpath", str(stdlib), "-d", str(artifact), str(SOURCE)])
        compile_path = os.pathsep.join((str(artifact), str(stdlib)))
        run([*compiler, *flags, "-classpath", compile_path, "-d", str(consumer), str(CONSUMER)])
        command = [java, "-cp", os.pathsep.join((compile_path, str(consumer))), MAIN]
        fixture_input = "\n".join(REFERENCE["fixtures"]()) + "\n"
        output = run(command, input=fixture_input)[0]
        report = {"status": "passed", "compiler": version, "runtime": runtime.splitlines()[0], "flags": flags,
                  "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                  "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                  "results": {key: int(value) for key, value in (line.split("=", 1) for line in output.splitlines())}}
        if measured:
            report["benchmark"] = benchmark(command)
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--kotlin-home", type=Path, default=os.environ.get("ABC_KOTLIN_HOME"))
    parser.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    if args.kotlin_home is None:
        parser.error("Select Kotlin 2.1.21 with --kotlin-home or ABC_KOTLIN_HOME")
    check(args.jdk, args.kotlin_home, args.benchmark)
