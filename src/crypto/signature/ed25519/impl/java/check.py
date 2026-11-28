"""Build an Ed25519 Java/Kotlin JAR and exercise it from a separate consumer."""

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
PACKAGE = "org.allbasket.abc.signature.ed25519"
JAVA = HERE / "src/org/allbasket/abc/signature/ed25519/Ed25519.java"
KOTLIN = HERE.parent / "kotlin/src/Ed25519.kt"
TEST = HERE / "tests/Checks.java"
OPENSSL = r"""
const crypto = require('node:crypto');
const {readFileSync} = require('node:fs');
const data = JSON.parse(readFileSync(0, 'utf8'));
const pkcs8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const output = data.map(([seed, message]) => {
  const key = crypto.createPrivateKey({
    key: Buffer.concat([pkcs8, Buffer.from(seed, 'hex')]), format: 'der', type: 'pkcs8',
  });
  const pub = crypto.createPublicKey(key);
  const data = Buffer.from(message, 'hex');
  const signature = crypto.sign(null, data, key);
  if (!crypto.verify(null, data, pub, signature)) throw new Error("OpenSSL verification failed");
  const raw = pub.export({format: 'der', type: 'spki'}).subarray(-32);
  return [seed, message, raw.toString('hex'), signature.toString('hex')].join(':');
});
console.log(JSON.stringify({node: process.version, openssl: process.versions.openssl, output}));
"""
RFC_VECTORS = (
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "72",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "af82",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
)


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
    rng = random.Random(803225519)
    boundary = (0, 1, 2, 31, 32, 63, 64, 65, 127, 128, 129, 257, 1024, 4097)
    sizes = [*boundary, *(rng.randrange(8193) for _ in range(96 - len(boundary)))]
    random_inputs = [(rng.randbytes(32).hex(), rng.randbytes(length).hex()) for length in sizes]
    rows = [*(vector[:2] for vector in RFC_VECTORS), *random_inputs]
    stdout, _ = run(["node", "-e", OPENSSL], input=json.dumps(rows))
    oracle = json.loads(stdout)
    if len(oracle["output"]) != len(rows) or oracle["output"][:len(RFC_VECTORS)] != [
        ":".join(vector) for vector in RFC_VECTORS
    ]:
        raise ValueError("OpenSSL failed a published vector or returned incomplete results")
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
    with tempfile.TemporaryDirectory(prefix="abc-jvm-ed25519-", dir=temporary_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(temporary_root):
            raise ValueError("Temporary work directory is outside its established root")
        source = JAVA if options.language == "java" else KOTLIN
        artifact = work / f"abc-ed25519-{options.language}.jar"
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
            target_test.write_text(code.replace(f"{PACKAGE}.Ed25519;", f"{PACKAGE}.kotlin.Ed25519;"),
                                   encoding="utf-8")
        consumer = work / "consumer"
        consumer.mkdir()
        jars = [artifact, *dependencies]
        run([javac, *compiler_flags, "-classpath", classpath(jars), "-d", str(consumer), str(target_test)])
        observed, _ = run([java, "-classpath", classpath([*jars, consumer]), "Checks"],
                          cwd=work, input="\n".join(oracle["output"]) + "\n")
        checks = dict(line.split("=", 1) for line in observed.splitlines())
        accepts = checks.pop("provider_identity_acceptances", None)
        expected = {"cases": str(len(oracle["output"])), "invalid_points": "12",
                    "strict_identity_rejections": "2", "provider_replacements_rejected": "1"}
        if checks != expected or accepts not in ("0", "1", "2"):
            raise ValueError(f"The consumer reported unexpected conformance counts: {checks}")
        report = {
            "status": "passed",
            "provider": "jdk.crypto.ec/sun.security.ec.SunEC",
            "runtime": details,
            "node": oracle["node"],
            "openssl": oracle["openssl"],
            "checks": {**checks, "rfc_known_answers": len(RFC_VECTORS),
                       "provider_identity_acceptances": int(accepts)},
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
