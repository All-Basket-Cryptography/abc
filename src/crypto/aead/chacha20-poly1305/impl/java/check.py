"""Build the Java ChaCha20-Poly1305 JAR and test it from a separate consumer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
SOURCE = HERE / "src/org/allbasket/abc/aead/chacha20poly1305/ChaCha20Poly1305.java"
TEST = HERE / "tests/Checks.java"
CHACHA = CRYPTO / "cipher/chacha20/impl/java/src/org/allbasket/abc/cipher/chacha20/ChaCha20.java"
POLY = CRYPTO / "mac/poly1305/impl/java/src/org/allbasket/abc/mac/poly1305/Poly1305.java"
OPENSSL = r"""
const { createCipheriv } = require('node:crypto');
const { readFileSync } = require('node:fs');
const fixtures = JSON.parse(readFileSync(0, 'utf8'));
const output = fixtures.map(fixture => {
  const [key, nonce, aad, message] = fixture.map(x => Buffer.from(x, 'hex'));
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, {authTagLength: 16});
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(message), cipher.final()]);
  return [...fixture, ciphertext.toString('hex'), cipher.getAuthTag().toString('hex')].join(':');
});
console.log(JSON.stringify({version: process.version, openssl: process.versions.openssl, output}));
"""
RFC = [
    bytes(range(128, 160)).hex(),
    "070000004041424344454647",
    "50515253c0c1c2c3c4c5c6c7",
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e",
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116",
    "1ae10b594f09e26a7e902ecbd0600691",
]


def run(command, **kwargs):
    result = subprocess.run(command, text=True, encoding="utf-8", capture_output=True,
                            timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout.strip(), result.stderr.strip()


def executable(jdk, name):
    binary = name + (".exe" if os.name == "nt" else "")
    return str(jdk.resolve() / "bin" / binary) if jdk else binary


def classpath(paths):
    return os.pathsep.join(map(str, paths))


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reference():
    rng = random.Random(843928)
    edges = (0, 1, 15, 16, 17, 63, 64, 65, 129)
    sizes = [(payload, aad) for payload in edges for aad in edges]
    sizes.extend((rng.randrange(8193), rng.randrange(513)) for _ in range(120))
    inputs = [[rng.randbytes(n).hex() for n in (32, 12, aad, payload)] for payload, aad in sizes]
    output, _ = run(["node", "-e", OPENSSL], input=json.dumps([RFC[:4], *inputs]))
    oracle = json.loads(output)
    if oracle["output"][0] != ":".join(RFC) or len(oracle["output"]) != len(inputs) + 1:
        raise ValueError("OpenSSL failed the RFC 8439 vector or produced too few results")
    return oracle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--output", type=Path, help="retain the tested JARs and receipt")
    options = parser.parse_args()
    java, javac, jar = (executable(options.jdk, name) for name in ("java", "javac", "jar"))
    stdout, stderr = run([java, "-version"])
    version = stdout or stderr
    if not re.search(r'version "17(?:\.|")', version):
        raise ValueError(f"Expected JDK 17, got {version}")
    oracle = reference()

    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-chacha20-poly1305-java-", dir=temporary_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(temporary_root):
            raise ValueError("Temporary work directory is outside its established root")
        flags = ["--release", "17", "-Xlint:all", "-Werror"]

        def build(name, source, dependencies=()):
            classes = work / name
            classes.mkdir()
            artifact = work / f"{name}.jar"
            class_args = ["-classpath", classpath(dependencies)] if dependencies else []
            run([javac, *flags, *class_args, "-d", str(classes), str(source)])
            run([jar, "--create", "--file", str(artifact), "--date", "2000-01-01T00:00:00Z",
                 "-C", str(classes), "."])
            return artifact

        primitives = [build("abc-chacha20", CHACHA), build("abc-poly1305", POLY)]
        artifact = build("abc-chacha20-poly1305", SOURCE, primitives)
        jars = [artifact, *primitives]
        consumer = build("consumer", TEST, jars)
        observed, _ = run([java, "-classpath", classpath([*jars, consumer]), "Checks"], cwd=work,
                          input="\n".join(oracle["output"]) + "\n")
        checks = dict(line.split("=", 1) for line in observed.splitlines())
        if checks != {"cases": str(len(oracle["output"])), "authentication_rejections": "23"}:
            raise ValueError(f"The consumer reported unexpected conformance counts: {checks}")
        report = {
            "status": "passed",
            "jdk": version,
            "python": platform.python_version(),
            "node": oracle["version"],
            "openssl": oracle["openssl"],
            "checks": {**checks, "rfc": 1},
            "source_sha256": fingerprint(SOURCE),
            "test_sha256": fingerprint(TEST),
            "artifacts_sha256": {path.name: fingerprint(path) for path in jars},
        }
        if options.output:
            output = options.output.resolve()
            output.mkdir(parents=True, exist_ok=True)
            for path in jars:
                shutil.copyfile(path, output / path.name)
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
