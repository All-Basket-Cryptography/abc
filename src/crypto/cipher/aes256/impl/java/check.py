"""Test the four Java and Kotlin SunJCE profile JARs from separate consumers."""

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
CRYPTO = HERE.parents[3]
PROFILES = {
    "aes256": ("cipher/aes256", "cipher.aes256", "Aes256"),
    "aes256-gcm": ("aead/aes256-gcm", "aead.aes256gcm", "Aes256Gcm"),
}
OPENSSL = r"""
const {createCipheriv, createDecipheriv} = require('node:crypto');
const {readFileSync} = require('node:fs');
const {mode, fixtures} = JSON.parse(readFileSync(0, 'utf8'));
const output = fixtures.map(row => {
  const [key, first, second, message] = row.map(field => Buffer.from(field, 'hex'));
  if (mode === 'aes256') {
    const enc = createCipheriv('aes-256-ecb', key, null).setAutoPadding(false);
    const dec = createDecipheriv('aes-256-ecb', key, null).setAutoPadding(false);
    const encrypted = Buffer.concat([enc.update(first), enc.final()]);
    const decrypted = Buffer.concat([dec.update(second), dec.final()]);
    return [...row, encrypted.toString('hex'), decrypted.toString('hex')].join(':');
  }
  const seal = createCipheriv('aes-256-gcm', key, first, {authTagLength: 16});
  seal.setAAD(second);
  const body = Buffer.concat([seal.update(message), seal.final()]);
  return [...row, body.toString('hex'), seal.getAuthTag().toString('hex')].join(':');
});
console.log(JSON.stringify({node: process.version, openssl: process.versions.openssl, output}));
"""
AES_BLOCK_VECTORS = (
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
    ("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"),
)
GCM_KEY = "feffe9928665731c6d6a8f9467308308" * 2
GCM_IV = "cafebabefacedbaddecaf888"
GCM_VECTORS = (
    (GCM_KEY, GCM_IV, "", "", "", "fd2caa16a5832e76aa132c1453eeda7e"),
    (GCM_KEY, GCM_IV, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d585",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
     "e097195f4532da895fb917a5a55c6aa0"),
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
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def classpath(paths):
    return os.pathsep.join(map(str, paths))


def reference(algorithm):
    rng = random.Random(19725638)
    if algorithm == "aes256":
        known = [(key, message, body, body, message) for key, message, body in AES_BLOCK_VECTORS]
        rows = [[rng.randbytes(n).hex() for n in (32, 16, 16)] for _ in range(512)]
    else:
        known = GCM_VECTORS
        edges = (0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 129)
        sizes = [(payload, aad) for payload in edges for aad in edges]
        sizes.extend((rng.randrange(8193), rng.randrange(513)) for _ in range(128))
        rows = [[rng.randbytes(n).hex() for n in (32, 12, aad, payload)] for payload, aad in sizes]
    known_inputs = [row[:-2] for row in known]
    payload = json.dumps({"mode": algorithm, "fixtures": [*known_inputs, *rows]})
    output, _ = run(["node", "-e", OPENSSL], input=payload)
    oracle = json.loads(output)
    if len(oracle["output"]) != len(known) + len(rows) or (
        oracle["output"][:len(known)] != [":".join(row) for row in known]
    ):
        raise ValueError("OpenSSL failed a published vector or returned incomplete results")
    return oracle


def runtime_details(java, expected):
    stdout, stderr = run([java, "-XshowSettings:properties", "-version"])
    details = stdout + "\n" + stderr
    properties = dict(re.findall(r"^    (java\.(?:home|vendor|runtime\.version)|os\.arch) = (.+)$", details, re.M))
    if not properties.get("java.runtime.version", "").startswith("17."):
        raise ValueError(f"Expected JDK 17, got {properties.get('java.runtime.version')}")
    home = Path(properties.pop("java.home"))
    module_hash = fingerprint(home / "lib/modules")
    if expected and module_hash != expected.lower():
        raise ValueError("Unexpected JDK module image SHA-256")
    image_candidates = (home / "bin/server/jvm.dll", home / "lib/server/libjvm.so",
                        home / "lib/server/libjvm.dylib")
    vm = next((fingerprint(path) for path in image_candidates if path.is_file()), None)
    stdout, stderr = run([java, "-XX:+UnlockDiagnosticVMOptions", "-XX:+PrintFlagsFinal", "-version"])
    flags = dict(re.findall(r"\b(UseAESIntrinsics|UseGHASHIntrinsics)\s*=\s*(true|false)", stdout + stderr))
    return {**properties, "module_image_sha256": module_hash, "vm_sha256": vm, "intrinsic_flags": flags}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--algorithm", choices=PROFILES, required=True)
    parser.add_argument("--language", choices=("java", "kotlin"), required=True)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--kotlin-home", type=Path, default=os.environ.get("ABC_KOTLIN_HOME"))
    parser.add_argument("--expect-modules-sha256")
    parser.add_argument("--output", type=Path, help="retain the tested JAR and receipt")
    options = parser.parse_args()
    java, javac, jar = (executable(options.jdk, name) for name in ("java", "javac", "jar"))
    details = runtime_details(java, options.expect_modules_sha256)
    oracle = reference(options.algorithm)
    profile, package_suffix, class_name = PROFILES[options.algorithm]
    package = f"org.allbasket.abc.{package_suffix}"
    leaf = CRYPTO / profile / "impl"
    test = leaf / "java/tests/Checks.java"
    javac_flags = ["--release", "17", "-Xlint:all", "-Werror"]
    work_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-aes-jvm-", dir=work_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(work_root):
            raise ValueError("Temporary work directory is outside its established root")
        artifact = work / f"abc-{options.algorithm}-{options.language}.jar"
        dependencies = []
        if options.language == "java":
            source = leaf / "java/src" / Path(package.replace(".", "/")) / f"{class_name}.java"
            classes = work / "classes"
            classes.mkdir()
            run([javac, *javac_flags, "-d", str(classes), str(source)])
            run([jar, "--create", "--file", str(artifact), "--date", "2000-01-01T00:00:00Z",
                 "-C", str(classes), "."])
            target_test = test
        else:
            if not options.kotlin_home:
                raise ValueError("Select Kotlin 2.1.21 with --kotlin-home or ABC_KOTLIN_HOME")
            kotlin_home = options.kotlin_home.resolve()
            library = kotlin_home / "lib"
            dependencies.append(library / "kotlin-stdlib.jar")
            compiler = [java, f"-Dkotlin.home={kotlin_home}", "-cp", str(library / "*"),
                        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
            stdout, stderr = run([*compiler, "-version"])
            compiler_version = stdout or stderr
            if not re.search(r"\bkotlinc-jvm 2\.1\.21\b", compiler_version):
                raise ValueError(f"Expected Kotlin 2.1.21, got {compiler_version}")
            details["kotlin_compiler"] = compiler_version
            details["kotlin_stdlib_sha256"] = fingerprint(dependencies[0])
            source = leaf / "kotlin/src" / f"{class_name}.kt"
            run([*compiler, "-Xjdk-release=17", "-Werror", "-no-stdlib", "-no-reflect",
                 "-classpath", classpath(dependencies), "-d", str(artifact), str(source)])
            target_test = work / "Checks.java"
            code = test.read_text(encoding="utf-8")
            target_test.write_text(code.replace(f"{package}.{class_name};",
                                                f"{package}.kotlin.{class_name};"), encoding="utf-8")

        jars = [artifact, *dependencies]
        consumer = work / "consumer"
        consumer.mkdir()
        run([javac, *javac_flags, "-classpath", classpath(jars), "-d", str(consumer), str(target_test)])
        observed, _ = run([java, "-classpath", classpath([*jars, consumer]), "Checks"],
                          cwd=work, input="\n".join(oracle["output"]) + "\n")
        checks = dict(line.split("=", 1) for line in observed.splitlines())
        expected = {"cases": str(len(oracle["output"])), "provider_replacements_rejected": "1"}
        if options.algorithm == "aes256-gcm":
            expected["authentication_rejections"] = "23"
        if checks != expected:
            raise ValueError(f"The consumer reported unexpected conformance counts: {checks}")
        report = {
            "status": "passed",
            "provider": "java.base/com.sun.crypto.provider.SunJCE",
            "runtime": details,
            "node": oracle["node"],
            "openssl": oracle["openssl"],
            "checks": {**checks, "known_answers": 2},
            "source_sha256": fingerprint(source),
            "test_sha256": fingerprint(test),
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
