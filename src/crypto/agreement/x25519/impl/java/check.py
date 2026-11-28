"""Build an X25519 Java/Kotlin JAR and exercise it from a separate consumer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
PACKAGE = "org.allbasket.abc.agreement.x25519"
JAVA = HERE / "src/org/allbasket/abc/agreement/x25519/X25519.java"
KOTLIN = HERE.parent / "kotlin/src/X25519.kt"
TEST = HERE / "tests/Checks.java"
OPENSSL = r"""
const crypto = require('node:crypto');
const {readFileSync} = require('node:fs');
const data = JSON.parse(readFileSync(0, 'utf8'));
const pkcs8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const spki = Buffer.from('302a300506032b656e032100', 'hex');
const priv = scalar => crypto.createPrivateKey({
  key: Buffer.concat([pkcs8, Buffer.from(scalar, 'hex')]), format: 'der', type: 'pkcs8',
});
const pub = privateKey => crypto.createPublicKey(privateKey).export({format: 'der', type: 'spki'}).subarray(-32);
const output = data.map(([scalar, u, derivePeer]) => {
  const local = priv(scalar);
  const point = derivePeer ? pub(priv(u)) : Buffer.from(u, 'hex');
  const publicKey = crypto.createPublicKey({key: Buffer.concat([spki, point]), format: 'der', type: 'spki'});
  const secret = crypto.diffieHellman({privateKey: local, publicKey});
  return [scalar, point.toString('hex'), pub(local).toString('hex'), secret.toString('hex')].join(':');
});
console.log(JSON.stringify({node: process.version, openssl: process.versions.openssl, output}));
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
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def classpath(paths):
    return os.pathsep.join(map(str, paths))


def reference():
    rng = random.Random(774825519)
    rows = [(rng.randbytes(32).hex(), rng.randbytes(32).hex(), i >= 128) for i in range(192)]
    field = (1 << 255) - 19
    scalar = bytes(range(32)).hex()
    rows.extend((scalar, u.to_bytes(32, "little").hex(), False)
                for u in (9, field + 9, (1 << 255) + 9, (1 << 255) + field + 9))
    stdout, _ = run(["node", "-e", OPENSSL], input=json.dumps(rows))
    oracle = json.loads(stdout)
    if len(oracle["output"]) != len(rows):
        raise ValueError("Incomplete OpenSSL reference output")
    return oracle


def runtime(java, expected):
    stdout, stderr = run([java, "-XshowSettings:properties", "-version"])
    properties = dict(re.findall(r"^    (java\.(?:home|vendor|runtime\.version)|os\.arch) = (.+)$",
                                 stdout + "\n" + stderr, re.M))
    if not properties.get("java.runtime.version", "").startswith("17."):
        raise ValueError(f"Expected JDK 17, got {properties.get('java.runtime.version')}")
    home = Path(properties.pop("java.home"))
    module_hash = fingerprint(home / "lib/modules")
    if expected and module_hash != expected.lower():
        raise ValueError("Unexpected JDK module image SHA-256")
    vm_candidates = (home / "bin/server/jvm.dll", home / "lib/server/libjvm.so",
                     home / "lib/server/libjvm.dylib")
    vm_hash = next((fingerprint(path) for path in vm_candidates if path.is_file()), None)
    return {**properties, "module_image_sha256": module_hash, "vm_sha256": vm_hash}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("java", "kotlin"), required=True)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--kotlin-home", type=Path, default=os.environ.get("ABC_KOTLIN_HOME"))
    parser.add_argument("--expect-modules-sha256")
    parser.add_argument("--output", type=Path, help="retain the tested JAR and receipt")
    options = parser.parse_args()
    java, javac, jar = (executable(options.jdk, name) for name in ("java", "javac", "jar"))
    details = runtime(java, options.expect_modules_sha256)
    oracle = reference()
    compiler_flags = ["--release", "17", "-Xlint:all", "-Werror"]
    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-jvm-x25519-", dir=temporary_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(temporary_root):
            raise ValueError("Temporary work directory is outside its established root")
        source = JAVA if options.language == "java" else KOTLIN
        artifact = work / f"abc-x25519-{options.language}.jar"
        dependencies = []
        target_test = TEST
        if options.language == "java":
            classes = work / "classes"
            classes.mkdir()
            run([javac, *compiler_flags, "-d", str(classes), str(source)])
            run([jar, "--create", "--file", str(artifact), "--date", "2000-01-01T00:00:00Z",
                 "-C", str(classes), "."])
        else:
            if not options.kotlin_home:
                raise ValueError("Select Kotlin 2.1.21 with --kotlin-home or ABC_KOTLIN_HOME")
            kotlin_home = options.kotlin_home.resolve()
            library = kotlin_home / "lib"
            dependencies = [library / "kotlin-stdlib.jar"]
            compiler = [java, f"-Dkotlin.home={kotlin_home}", "-cp", str(library / "*"),
                        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
            stdout, stderr = run([*compiler, "-version"])
            compiler_version = stdout or stderr
            if not re.search(r"\bkotlinc-jvm 2\.1\.21\b", compiler_version):
                raise ValueError(f"Expected Kotlin 2.1.21, got {compiler_version}")
            details["kotlin_compiler"] = compiler_version
            details["kotlin_stdlib_sha256"] = fingerprint(dependencies[0])
            run([*compiler, "-Xjdk-release=17", "-Werror", "-no-stdlib", "-no-reflect",
                 "-classpath", classpath(dependencies), "-d", str(artifact), str(source)])
            target_test = work / "Checks.java"
            code = TEST.read_text(encoding="utf-8")
            target_test.write_text(code.replace(f"{PACKAGE}.X25519;", f"{PACKAGE}.kotlin.X25519;"),
                                   encoding="utf-8")
        consumer = work / "consumer"
        consumer.mkdir()
        jars = [artifact, *dependencies]
        run([javac, *compiler_flags, "-classpath", classpath(jars), "-d", str(consumer), str(target_test)])
        observed, _ = run([java, "-classpath", classpath([*jars, consumer]), "Checks"],
                          cwd=work, input="\n".join(oracle["output"]) + "\n")
        checks = dict(line.split("=", 1) for line in observed.splitlines())
        expected = {"cases": str(len(oracle["output"])), "rfc_known_answers": "6",
                    "private_clamp_aliases": "32", "peer_aliases": "3",
                    "low_order_rejections": "14", "provider_replacements_rejected": "1"}
        if checks != expected:
            raise ValueError(f"The consumer reported unexpected conformance counts: {checks}")
        report = {
            "status": "passed",
            "provider": "jdk.crypto.ec/sun.security.ec.SunEC",
            "runtime": details,
            "node": oracle["node"],
            "openssl": oracle["openssl"],
            "checks": checks,
            "source_sha256": fingerprint(source),
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
