"""Compile a pure Java BLAKE2b JAR and compare it in a separate consumer."""

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
SOURCE = HERE / "src/org/allbasket/abc/hash/blake2b/Blake2b.java"
TEST = HERE / "tests/Checks.java"
LENGTHS = (0, 1, 127, 128, 129, 255, 256, 257, 1000)
REFERENCE = r"""
const {createHash} = require('node:crypto');
const {readFileSync} = require('node:fs');
const input = readFileSync(0, 'utf8').trimEnd().split(/\r?\n/);
console.log(JSON.stringify({
  node: process.version,
  openssl: process.versions.openssl,
  results: input.map(message => createHash('blake2b512').update(Buffer.from(message, 'hex')).digest('hex')),
}));
"""


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

    messages = [bytes((37 * i + 11) % 256 for i in range(size)) for size in LENGTHS]
    output, _ = run(["node", "-e", REFERENCE], input="\n".join(message.hex() for message in messages) + "\n")
    reference = json.loads(output)
    if reference["results"] != [hashlib.blake2b(message).hexdigest() for message in messages]:
        raise ValueError("OpenSSL disagrees with the independent CPython BLAKE2b-512 outputs")
    fixtures = "\n".join(
        f"{message.hex()}:{hashlib.blake2b(message, digest_size=size).hexdigest()}"
        for message in messages for size in range(1, 65)
    ) + "\n"
    splits = 3 * sum(len(message) + 1 for message in messages)

    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-blake2b-java-", dir=temporary_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(temporary_root):
            raise ValueError("Temporary work directory is outside its established root")
        classes, consumer = work / "classes", work / "consumer"
        classes.mkdir()
        consumer.mkdir()
        artifact = work / "abc-blake2b.jar"
        flags = ["--release", "17", "-Xlint:all", "-Werror"]
        run([javac, *flags, "-d", str(classes), str(SOURCE)])
        run([jar, "--create", "--file", str(artifact), "--date", "2000-01-01T00:00:00Z",
             "-C", str(classes), "."])
        run([javac, *flags, "-classpath", str(artifact), "-d", str(consumer), str(TEST)])
        observed, _ = run([java, "-classpath", os.pathsep.join(map(str, (artifact, consumer))), "Checks"],
                          cwd=work, input=fixtures)
        checks = dict(line.split("=", 1) for line in observed.splitlines())
        if checks != {"cases": str(len(messages) * 64), "splits": str(splits)}:
            raise ValueError("The consumer did not report the requested fixture counts")
        report = {
            "status": "passed",
            "jdk": version,
            "python": platform.python_version(),
            "node": reference["node"],
            "openssl": reference["openssl"],
            "checks": {**checks, "openssl_comparisons": len(messages)},
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
