"""Compile and run the independent Kotlin SHA-512 core on Kotlin 2.1.21 and JDK 17."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "src/Sha512.kt"
TEST = HERE / "tests/Sha512Checks.kt"
MAIN = "org.allbasket.abc.hash.sha512.kotlin.Sha512ChecksKt"
COMPILER_VERSION = "2.1.21"


def fingerprint(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check(jdk, kotlin, output):
    name = "java.exe" if os.name == "nt" else "java"
    java = str(jdk.resolve() / "bin" / name) if jdk else name
    runtime = subprocess.check_output([java, "-version"], stderr=subprocess.STDOUT, text=True, timeout=15)
    if not re.search(r'version "17(?:\.|")', runtime):
        raise ValueError("The qualification run requires JDK 17")
    distribution = kotlin.resolve()
    libraries = distribution / "lib"
    stdlib = libraries / "kotlin-stdlib.jar"
    compiler = [java, f"-Dkotlin.home={distribution}", "-cp", str(libraries / "*"),
                "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
    version = subprocess.check_output([*compiler, "-version"], stderr=subprocess.STDOUT, text=True, timeout=30).strip()
    if not re.search(rf"\bkotlinc-jvm {re.escape(COMPILER_VERSION)}\b", version):
        raise ValueError(f"Expected Kotlin {COMPILER_VERSION}, found {version}")

    output.mkdir(parents=True, exist_ok=True)
    artifact = output / "abc-sha512-kotlin.jar"
    flags = ["-Xjdk-release=17", "-Werror", "-no-stdlib", "-no-reflect"]
    subprocess.run([*compiler, *flags, "-classpath", str(stdlib), "-d", str(artifact), str(SOURCE)],
                   check=True, timeout=90)
    with TemporaryDirectory(prefix="abc-sha512-kotlin-consumer-") as directory:
        tests = Path(directory) / "tests.jar"
        test_classpath = os.pathsep.join((str(artifact), str(stdlib)))
        subprocess.run([*compiler, *flags, "-classpath", test_classpath, f"-Xfriend-paths={artifact}",
                        "-d", str(tests), str(TEST)], check=True, timeout=90)
        observed = subprocess.check_output([java, "-cp", os.pathsep.join((test_classpath, str(tests))), MAIN],
                                           text=True, timeout=90)
    report = {
        "status": "passed",
        "compiler": version,
        "compile_flags": flags,
        "source_sha256": fingerprint(SOURCE),
        "test_sha256": fingerprint(TEST),
        "stdlib_sha256": fingerprint(stdlib),
        "artifact_sha256": fingerprint(artifact),
        "checks": dict(line.split("=", 1) for line in observed.splitlines()),
    }
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--kotlin-home", type=Path, default=os.environ.get("ABC_KOTLIN_HOME"))
    parser.add_argument("--output", type=Path, help="retain the JAR and check report")
    options = parser.parse_args()
    if options.kotlin_home is None:
        parser.error("Select the Kotlin 2.1.21 distribution with --kotlin-home or ABC_KOTLIN_HOME")
    if options.output:
        result = check(options.jdk, options.kotlin_home, options.output.resolve())
    else:
        with TemporaryDirectory(prefix="abc-sha512-kotlin-") as directory:
            result = check(options.jdk, options.kotlin_home, Path(directory))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
