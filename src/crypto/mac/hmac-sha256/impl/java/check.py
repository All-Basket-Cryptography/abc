"""Compile native Java cores into separate JARs and run a clean JDK 17 consumer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
SHA = CRYPTO / "hash/sha256/impl/java/src/org/allbasket/abc/hash/sha256/Sha256.java"
HMAC = HERE / "src/org/allbasket/abc/mac/hmacsha256/HmacSha256.java"
FLAGS = ["--release", "17", "-encoding", "UTF-8", "-Xlint:all", "-Werror"]


def check(jdk, libraries, test_source, test_name):
    def tool(name):
        suffix = ".exe" if os.name == "nt" else ""
        return str(jdk / "bin" / (name + suffix)) if jdk else name

    def run(name, *args):
        result = subprocess.run([tool(name), *args], capture_output=True, text=True, timeout=90, check=False)
        if result.returncode:
            raise RuntimeError(f"{name} exited {result.returncode}\n{result.stdout}{result.stderr}")
        return result.stdout.strip()

    compiler = run("javac", "-version")
    if not (compiler == "javac 17" or compiler.startswith("javac 17.")):
        raise ValueError(f"Expected JDK 17, got {compiler}")
    with TemporaryDirectory(prefix="abc-jdk17-check-") as directory:
        work = Path(directory)
        class_path = []
        for name, source in libraries:
            classes = work / name
            classes.mkdir()
            archive = work / f"{name}.jar"
            dependencies = ["-cp", os.pathsep.join(class_path)] if class_path else []
            run("javac", *FLAGS, *dependencies, "-d", str(classes), str(source))
            run("jar", "--create", "--file", str(archive), "-C", str(classes), ".")
            class_path.append(str(archive))
        tests = work / "consumer"
        tests.mkdir()
        run("javac", *FLAGS, "-cp", os.pathsep.join(class_path), "-d", str(tests), str(test_source))
        report = json.loads(run("java", "-cp", os.pathsep.join([*class_path, str(tests)]), test_name))
    report["compiler"] = compiler
    report["sources_sha256"] = {
        source.relative_to(CRYPTO).as_posix(): hashlib.sha256(source.read_bytes()).hexdigest()
        for source in [*(path for _, path in libraries), test_source]
    }
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", default=os.environ.get("ABC_JAVA_HOME"), type=Path)
    options = parser.parse_args()
    test = HERE / "tests/org/allbasket/abc/mac/hmacsha256/HmacSha256Checks.java"
    name = "org.allbasket.abc.mac.hmacsha256.HmacSha256Checks"
    print(json.dumps(check(options.jdk, [("sha256", SHA), ("hmac-sha256", HMAC)], test, name), indent=2))
