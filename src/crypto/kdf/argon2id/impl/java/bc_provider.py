"""Verify the BC artifact and test an SDK JAR with an isolated JVM consumer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
from urllib.request import urlopen


PIN_FILE = Path(__file__).with_name("bcprov.toml")
PIN = tomllib.loads(PIN_FILE.read_text(encoding="utf-8"))
PROVIDER_NAME = f'{PIN["artifact"]}-{PIN["version"]}.jar'


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
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def provider_archive(work, supplied):
    if supplied is not None:
        archive = supplied.resolve()
    else:
        archive = work / PROVIDER_NAME
        group = PIN["group"].replace(".", "/")
        route = f'{group}/{PIN["artifact"]}/{PIN["version"]}/{PROVIDER_NAME}'
        with urlopen(f"https://repo.maven.apache.org/maven2/{route}", timeout=45) as response:
            data = response.read(PIN["jar_bytes"] + 1)
        if len(data) != PIN["jar_bytes"]:
            raise ValueError("Unexpected Bouncy Castle archive length")
        archive.write_bytes(data)
    if archive.stat().st_size != PIN["jar_bytes"] or fingerprint(archive) != PIN["jar_sha256"]:
        raise ValueError("Bouncy Castle archive does not match its exact release pin")
    return archive


def main(leaf, profile, package, class_name, verify):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("java", "kotlin"), required=True)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--kotlin-home", type=Path, default=os.environ.get("ABC_KOTLIN_HOME"))
    parser.add_argument("--bcprov", type=Path, default=os.environ.get("ABC_BCPROV_JAR"))
    parser.add_argument("--output", type=Path, help="retain the tested SDK JAR and receipt")
    options = parser.parse_args()
    java, javac, jar = (executable(options.jdk, name) for name in ("java", "javac", "jar"))
    stdout, stderr = run([java, "-version"])
    runtime = stdout or stderr
    if not re.search(r'version "17(?:\.|")', runtime):
        raise ValueError(f"Expected JDK 17, got {runtime}")

    work_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix=f"abc-{profile}-jvm-", dir=work_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(work_root):
            raise ValueError("Temporary work directory is outside its established root")
        provider = provider_archive(work, options.bcprov)
        dependencies = [provider]
        sdk = work / f"abc-{profile}-{options.language}.jar"
        flags = ["--release", "17", "-Xlint:all", "-Werror"]
        test = leaf / "tests/Checks.java"
        target_test = test
        kotlin = None
        if options.language == "java":
            source = leaf / "src" / package.replace(".", "/") / f"{class_name}.java"
            classes = work / "classes"
            classes.mkdir()
            run([javac, *flags, "-classpath", classpath(dependencies), "-d", str(classes), str(source)])
            run([jar, "--create", "--file", str(sdk), "--date", "2000-01-01T00:00:00Z",
                 "-C", str(classes), "."])
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
            source = leaf.parent / "kotlin/src" / f"{class_name}.kt"
            run([*compiler, "-Xjdk-release=17", "-Werror", "-no-stdlib", "-no-reflect",
                 "-classpath", classpath(dependencies), "-d", str(sdk), str(source)])
            target_test = work / "Checks.java"
            code = test.read_text(encoding="utf-8")
            target_test.write_text(code.replace(f"{package}.{class_name};",
                                                f"{package}.kotlin.{class_name};"), encoding="utf-8")

        consumer = work / "consumer"
        consumer.mkdir()
        jars = [sdk, *dependencies]
        run([javac, *flags, "-classpath", classpath(jars), "-d", str(consumer), str(target_test)])

        def invoke(*args, wire=""):
            return run([java, "-Xmx384m", "-classpath", classpath([*jars, consumer]), "Checks", *args],
                       cwd=work, input=wire)[0]

        evidence = verify(invoke)
        report = {
            "status": "passed",
            "jdk": runtime,
            "kotlin": kotlin,
            "provider": PIN,
            "checks": evidence,
            "source_sha256": fingerprint(source),
            "test_sha256": fingerprint(test),
            "artifact_sha256": fingerprint(sdk),
        }
        if options.output:
            output = options.output.resolve()
            output.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sdk, output / sdk.name)
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
