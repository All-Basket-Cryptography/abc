"""Build the independent Java 17 core and test the packaged JAR as a consumer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
PACKAGE = "org.allbasket.abc.hash.sha256"
SOURCE = HERE / "src/org/allbasket/abc/hash/sha256/Sha256.java"
TEST = HERE / "tests/org/allbasket/abc/hash/sha256/Sha256Checks.java"


def tool(name, jdk):
    if jdk is None:
        return name
    executable = name + ".exe" if os.name == "nt" else name
    return str(jdk.resolve() / "bin" / executable)


def fingerprint(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check(jdk, output):
    java, javac, jar = (tool(name, jdk) for name in ("java", "javac", "jar"))
    compiler = subprocess.check_output([javac, "-version"], text=True, stderr=subprocess.STDOUT).strip()
    if not (compiler == "javac 17" or compiler.startswith("javac 17.")):
        raise ValueError(f"The qualification run requires JDK 17, found {compiler}")

    output.mkdir(parents=True, exist_ok=True)
    artifact = output / "abc-sha256-pure-java.jar"
    flags = ["--release", "17", "-encoding", "UTF-8", "-Xlint:all", "-Werror"]
    with TemporaryDirectory(prefix="abc-sha256-java-classes-") as temporary:
        build = Path(temporary)
        classes, tests = build / "classes", build / "tests"
        classes.mkdir()
        tests.mkdir()
        subprocess.run([javac, *flags, "-d", str(classes), str(SOURCE)], check=True, timeout=90)
        subprocess.run([jar, "--create", "--file", str(artifact), "-C", str(classes), "."], check=True, timeout=90)
        subprocess.run([javac, *flags, "-cp", str(artifact), "-d", str(tests), str(TEST)], check=True, timeout=90)
        observed = subprocess.check_output([java, "-cp", os.pathsep.join((str(artifact), str(tests))),
                                            f"{PACKAGE}.Sha256Checks"], text=True, timeout=90)
    results = dict(line.split("=", 1) for line in observed.splitlines())
    report = {
        "status": "passed",
        "compiler": compiler,
        "compile_flags": flags,
        "source_sha256": fingerprint(SOURCE),
        "consumer_sha256": fingerprint(TEST),
        "artifact_sha256": fingerprint(artifact),
        "checks": results,
    }
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"),
                        help="JDK 17 root, or use ABC_JAVA_HOME and then PATH")
    parser.add_argument("--output", type=Path, help="retain the JAR and check report")
    options = parser.parse_args()
    if options.output:
        report = check(options.jdk, options.output.resolve())
    else:
        with TemporaryDirectory(prefix="abc-sha256-java-") as directory:
            report = check(options.jdk, Path(directory))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
