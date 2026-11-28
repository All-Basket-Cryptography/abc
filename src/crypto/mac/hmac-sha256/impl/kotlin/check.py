"""Compile and test the native Kotlin HMAC-SHA-256 core on Kotlin 2.1.21 and JDK 17."""

import argparse
import json
import os
from pathlib import Path
from runpy import run_path
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
SHA256 = HERE.parents[3] / "hash/sha256/impl/kotlin"
SOURCE = HERE / "src/HmacSha256.kt"
TEST = HERE / "tests/HmacSha256Checks.kt"
MAIN = "org.allbasket.abc.mac.hmacsha256.kotlin.HmacSha256ChecksKt"


def check(jdk, kotlin, output):
    sha_check = run_path(str(SHA256 / "check.py"))
    sha = sha_check["check"](jdk, kotlin, output / "sha256")
    fingerprint = sha_check["fingerprint"]
    java_name = "java.exe" if os.name == "nt" else "java"
    java = str(jdk.resolve() / "bin" / java_name) if jdk else java_name
    kotlin = kotlin.resolve()
    libraries = kotlin / "lib"
    compiler = [java, f"-Dkotlin.home={kotlin}", "-cp", str(libraries / "*"),
                "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
    stdlib = libraries / "kotlin-stdlib.jar"
    sha_jar = output / "sha256/abc-sha256-kotlin.jar"
    hmac_jar = output / "abc-hmac-sha256-kotlin.jar"
    classpath = os.pathsep.join((str(sha_jar), str(stdlib)))
    flags = sha["compile_flags"]
    subprocess.run([*compiler, *flags, "-classpath", classpath, "-d", str(hmac_jar), str(SOURCE)],
                   check=True, timeout=90)
    with TemporaryDirectory(prefix="abc-hmac-kotlin-consumer-") as directory:
        tests = Path(directory) / "tests.jar"
        classpath = os.pathsep.join((str(hmac_jar), classpath))
        subprocess.run([*compiler, *flags, "-classpath", classpath, "-d", str(tests), str(TEST)],
                       check=True, timeout=90)
        observed = subprocess.check_output([java, "-cp", os.pathsep.join((str(tests), classpath)), MAIN],
                                           text=True, timeout=90)
    checks = dict(line.split("=", 1) for line in observed.splitlines())
    for name, value in {"known_answers": "3", "one_shot_comparisons": "153", "streaming_snapshots": "312",
                        "invalid_range_and_ownership": "passed"}.items():
        if checks.get(name) != value:
            raise ValueError(f"Unexpected HMAC test result for {name}")
    report = {
        "status": "passed", "compiler": sha["compiler"], "runtime": sha["checks"]["runtime"],
        "architecture": sha["checks"]["architecture"], "source_sha256": fingerprint(SOURCE),
        "test_sha256": fingerprint(TEST), "artifact_sha256": fingerprint(hmac_jar),
        "sha256_dependency_source": sha["source_sha256"], "sha256_dependency_artifact": sha["artifact_sha256"],
        "stdlib_sha256": sha["stdlib_sha256"], "checks": checks,
    }
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--kotlin-home", type=Path, default=os.environ.get("ABC_KOTLIN_HOME"))
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    if options.kotlin_home is None:
        parser.error("Select the Kotlin 2.1.21 distribution with --kotlin-home or ABC_KOTLIN_HOME")
    if options.output:
        result = check(options.jdk, options.kotlin_home, options.output.resolve())
    else:
        with TemporaryDirectory(prefix="abc-hmac-kotlin-") as directory:
            result = check(options.jdk, options.kotlin_home, Path(directory))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
