"""Build the Kotlin HKDF-SHA-256 core and run a separate JDK 17 consumer."""

import argparse
import json
import os
from pathlib import Path
from runpy import run_path
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
HMAC = HERE.parents[3] / "mac/hmac-sha256/impl/kotlin"
SOURCE = HERE / "src/HkdfSha256.kt"
TEST = HERE / "tests/HkdfSha256Checks.kt"
MAIN = "org.allbasket.abc.kdf.hkdfsha256.kotlin.HkdfSha256ChecksKt"


def check(jdk, kotlin, output):
    dependency_dir = output / "hmac"
    hmac = run_path(str(HMAC / "check.py"))["check"](jdk, kotlin, dependency_dir)
    sha = json.loads((dependency_dir / "sha256/result.json").read_text(encoding="utf-8"))
    fingerprint = run_path(str(HERE.parents[3] / "hash/sha256/impl/kotlin/check.py"))["fingerprint"]
    java_name = "java.exe" if os.name == "nt" else "java"
    java = str(jdk.resolve() / "bin" / java_name) if jdk else java_name
    kotlin = kotlin.resolve()
    libraries = kotlin / "lib"
    compiler = [java, f"-Dkotlin.home={kotlin}", "-cp", str(libraries / "*"),
                "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
    runtime_jars = [dependency_dir / "sha256/abc-sha256-kotlin.jar",
                    dependency_dir / "abc-hmac-sha256-kotlin.jar", libraries / "kotlin-stdlib.jar"]
    artifact = output / "abc-hkdf-sha256-kotlin.jar"
    flags = sha["compile_flags"]
    classpath = os.pathsep.join(map(str, runtime_jars))
    subprocess.run([*compiler, *flags, "-classpath", classpath, "-d", str(artifact), str(SOURCE)],
                   check=True, timeout=90)
    with TemporaryDirectory(prefix="abc-hkdf-sha256-kotlin-consumer-") as directory:
        consumer = Path(directory) / "tests.jar"
        classpath = os.pathsep.join((classpath, str(artifact)))
        subprocess.run([*compiler, *flags, "-classpath", classpath, "-d", str(consumer), str(TEST)],
                       check=True, timeout=90)
        observed = subprocess.check_output(
            [java, "-cp", os.pathsep.join((classpath, str(consumer))), MAIN],
            text=True, timeout=90
        )
    checks = dict(line.split("=", 1) for line in observed.splitlines())
    for name, value in {"known_answers": "2", "differential_comparisons": "70",
                        "max_output_and_rejection": "passed"}.items():
        if checks.get(name) != value:
            raise ValueError(f"Unexpected HKDF-SHA-256 test result for {name}")
    report = {
        "status": "passed", "compiler": hmac["compiler"], "runtime": hmac["runtime"],
        "architecture": hmac["architecture"], "source_sha256": fingerprint(SOURCE),
        "test_sha256": fingerprint(TEST), "artifact_sha256": fingerprint(artifact),
        "hmac_dependency_source": hmac["source_sha256"], "hmac_dependency_artifact": hmac["artifact_sha256"],
        "sha256_dependency_source": sha["source_sha256"], "sha256_dependency_artifact": sha["artifact_sha256"],
        "stdlib_sha256": sha["stdlib_sha256"], "checks": checks,
    }
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--kotlin-home", type=Path, default=os.environ.get("ABC_KOTLIN_HOME"))
    parser.add_argument("--output", type=Path, help="retain the tested JAR and report")
    options = parser.parse_args()
    if options.kotlin_home is None:
        parser.error("Select the Kotlin 2.1.21 distribution with --kotlin-home or ABC_KOTLIN_HOME")
    if options.output:
        report = check(options.jdk, options.kotlin_home, options.output.resolve())
    else:
        with TemporaryDirectory(prefix="abc-hkdf-sha256-kotlin-") as directory:
            report = check(options.jdk, options.kotlin_home, Path(directory))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
