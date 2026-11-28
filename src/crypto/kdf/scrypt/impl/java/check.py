"""Test native Java and Kotlin scrypt JARs against OpenSSL."""

import argparse
import hashlib
from itertools import product
import json
import os
from pathlib import Path
import platform
import re
import shutil
import ssl
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
BASE_PACKAGE = "org.allbasket.abc"
JAVA_SOURCES = (
    ("hash/sha256", "hash/sha256/Sha256"),
    ("mac/hmac-sha256", "mac/hmacsha256/HmacSha256"),
    ("kdf/pbkdf2-hmac-sha256", "kdf/pbkdf2sha256/Pbkdf2Sha256"),
    ("kdf/scrypt", "kdf/scrypt/Scrypt"),
)
TEST = HERE / "tests/Checks.java"
RFC = (
    (b"", b"", 16, 1, 1,
     "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fc"
     "d0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
    (b"password", b"NaCl", 1024, 8, 16,
     "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622"
     "eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
    (b"pleaseletmein", b"SodiumChloride", 16384, 8, 1,
     "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
     "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"),
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
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classpath(paths):
    return os.pathsep.join(map(str, paths))


def fixtures():
    for password, salt, cost, block, parallel, expected in RFC:
        oracle = hashlib.scrypt(password, salt=salt, n=cost, r=block, p=parallel, dklen=64,
                                maxmem=64 * 1024**2).hex()
        if oracle != expected:
            raise ValueError("OpenSSL disagrees with the RFC 7914 vector")
        yield password, salt, cost, block, parallel, expected
    params = product((2, 4, 16, 32), (1, 2, 4), (1, 2, 3), (1, 32, 33, 71))
    for trial, (cost, block, parallel, size) in enumerate(params):
        password = bytes((trial * 47 + i * 91) % 256 for i in range(trial % 76))
        salt = bytes((trial * 81 + i * 71) % 256 for i in range(trial * 13 % 68))
        expected = hashlib.scrypt(password, salt=salt, n=cost, r=block, p=parallel, dklen=size,
                                  maxmem=64 * 1024**2).hex()
        yield password, salt, cost, block, parallel, expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("java", "kotlin"), required=True)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--kotlin-home", type=Path, default=os.environ.get("ABC_KOTLIN_HOME"))
    parser.add_argument("--output", type=Path, help="retain the test JARs and receipt")
    options = parser.parse_args()
    java, javac, jar = (executable(options.jdk, name) for name in ("java", "javac", "jar"))
    stdout, stderr = run([java, "-version"])
    jdk = stdout or stderr
    if not re.search(r'version "17(?:\.|")', jdk):
        raise ValueError(f"Expected JDK 17, got {jdk}")
    rows = list(fixtures())
    wire = "".join(f"{pw.hex()}:{salt.hex()}:{n}:{r}:{p}:{expected}\n"
                   for pw, salt, n, r, p, expected in rows)
    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-jvm-scrypt-", dir=temporary_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(temporary_root):
            raise ValueError("Temporary work directory is outside its established root")
        javac_flags = ["--release", "17", "-Xlint:all", "-Werror"]
        dependencies = []
        target_test = TEST
        kotlin = None
        if options.language == "java":
            def build(name, source, imports):
                output = work / f"{name}.jar"
                classes = work / name
                classes.mkdir()
                cp = ["-classpath", classpath(imports)] if imports else []
                run([javac, *javac_flags, *cp, "-d", str(classes), str(source)])
                run([jar, "--create", "--file", str(output), "--date", "2000-01-01T00:00:00Z",
                     "-C", str(classes), "."])
                return output
        else:
            if not options.kotlin_home:
                raise ValueError("Select Kotlin 2.1.21 with --kotlin-home or ABC_KOTLIN_HOME")
            kotlin_home = options.kotlin_home.resolve()
            library = kotlin_home / "lib"
            dependencies.append(library / "kotlin-stdlib.jar")
            compiler = [java, f"-Dkotlin.home={kotlin_home}", "-cp", str(library / "*"),
                        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
            stdout, stderr = run([*compiler, "-version"])
            kotlin = stdout or stderr
            if not re.search(r"\bkotlinc-jvm 2\.1\.21\b", kotlin):
                raise ValueError(f"Expected Kotlin 2.1.21, got {kotlin}")

            def build(name, source, imports):
                output = work / f"{name}.jar"
                run([*compiler, "-Xjdk-release=17", "-Werror", "-no-stdlib", "-no-reflect",
                     "-classpath", classpath(imports), "-d", str(output), str(source)])
                return output

            target_test = work / "Checks.java"
            code = TEST.read_text(encoding="utf-8")
            target_test.write_text(code.replace(f"{BASE_PACKAGE}.kdf.scrypt.Scrypt;",
                                                f"{BASE_PACKAGE}.kdf.scrypt.kotlin.Scrypt;"),
                                   encoding="utf-8")

        artifacts = []
        sources = {}
        for algorithm, java_name in JAVA_SOURCES:
            leaf = CRYPTO / algorithm / "impl" / options.language / "src"
            if options.language == "java":
                source = leaf / Path(BASE_PACKAGE.replace(".", "/")) / f"{java_name}.java"
            else:
                source = leaf / (java_name.rsplit("/", 1)[1] + ".kt")
            name = f"abc-{algorithm.split('/')[-1]}-{options.language}"
            artifacts.append(build(name, source, dependencies))
            dependencies.append(artifacts[-1])
            sources[name] = fingerprint(source)
        consumer = work / "consumer"
        consumer.mkdir()
        run([javac, *javac_flags, "-classpath", classpath(dependencies),
             "-d", str(consumer), str(target_test)])
        stdout, _ = run([java, "-Xmx256m", "-classpath", classpath([*dependencies, consumer]), "Checks"],
                        cwd=work, input=wire)
        checks = dict(line.split("=", 1) for line in stdout.splitlines())
        if checks != {"cases": str(len(rows)), "one_byte_under_budget_rejections": str(len(rows)),
                      "malformed_parameters_rejected": "11"}:
            raise ValueError(f"The consumer reported unexpected conformance counts: {checks}")
        report = {
            "status": "passed",
            "jdk": jdk,
            "kotlin": kotlin,
            "python": platform.python_version(),
            "openssl": ssl.OPENSSL_VERSION,
            "checks": {**checks, "rfc_known_answers": len(RFC)},
            "sources_sha256": sources,
            "test_sha256": fingerprint(TEST),
            "artifacts_sha256": {path.name: fingerprint(path) for path in artifacts},
        }
        if options.output:
            output_dir = options.output.resolve()
            output_dir.mkdir(parents=True, exist_ok=True)
            for path in artifacts:
                shutil.copyfile(path, output_dir / path.name)
            (output_dir / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
