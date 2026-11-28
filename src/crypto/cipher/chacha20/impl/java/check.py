"""Compile the ChaCha20 JAR and test it from a separate Java consumer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "src/org/allbasket/abc/cipher/chacha20/ChaCha20.java"
TEST = HERE / "tests/Checks.java"


def run(command, **kwargs):
    result = subprocess.run(command, text=True, encoding="utf-8", capture_output=True,
                            timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout.strip(), result.stderr.strip()


def executable(jdk, name):
    binary = name + (".exe" if os.name == "nt" else "")
    return str(jdk.resolve() / "bin" / binary) if jdk else binary


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--output", type=Path, help="retain the tested JAR and receipt")
    options = parser.parse_args()
    java, javac, jar = (executable(options.jdk, name) for name in ("java", "javac", "jar"))
    stdout, stderr = run([java, "-version"])
    version = stdout or stderr
    if not re.search(r'version "17(?:\.|")', version):
        raise ValueError(f"Expected JDK 17, got {version}")

    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-chacha20-java-", dir=temporary_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(temporary_root):
            raise ValueError("Temporary work directory is outside its established root")
        classes, consumer = work / "classes", work / "consumer"
        classes.mkdir()
        consumer.mkdir()
        artifact = work / "abc-chacha20.jar"
        flags = ["--release", "17", "-Xlint:all", "-Werror"]
        run([javac, *flags, "-d", str(classes), str(SOURCE)])
        run([jar, "--create", "--file", str(artifact), "--date", "2000-01-01T00:00:00Z",
             "-C", str(classes), "."])
        run([javac, *flags, "-classpath", str(artifact), "-d", str(consumer), str(TEST)])
        observed, _ = run([java, "-classpath", os.pathsep.join(map(str, (artifact, consumer))), "Checks"],
                          cwd=work)
        checks = dict(line.split("=", 1) for line in observed.splitlines())
        if checks != {"provider": "SunJCE", "cases": "79", "splits": "3959"}:
            raise ValueError(f"The consumer reported unexpected conformance counts: {checks}")
        report = {
            "status": "passed",
            "jdk": version,
            "python": platform.python_version(),
            "checks": checks,
            "source_sha256": fingerprint(SOURCE),
            "test_sha256": fingerprint(TEST),
            "artifact_sha256": fingerprint(artifact),
        }
        if options.output:
            output = options.output.resolve()
            output.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(artifact, output / artifact.name)
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
