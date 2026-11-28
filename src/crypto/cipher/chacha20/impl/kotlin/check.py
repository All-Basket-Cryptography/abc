"""Compile Kotlin RFC 8439 modules and independently build offline JAR consumers."""

import argparse
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
CS_FIXTURES = HERE.parent / "csharp/check.py"
KOTLIN = "2.1.21"
MAIN = "org.allbasket.abc.conformance.rfc8439.ChecksKt"


def check(java, kotlin, openssl, selected, output):
    harness = runpy.run_path(str(CS_FIXTURES))
    oracle = runpy.run_path(str(harness["C_ORACLE"]))
    resolver = harness["PROFILES"]
    tested = list(resolver) if selected == "all" else [selected]
    built = list(resolver) if selected in ("all", "aead") else tested
    run = harness["run"]
    fingerprint = harness["fingerprint"]
    libs = kotlin / "lib"
    stdlib = libs / "kotlin-stdlib.jar"
    compiler = [java, f"-Dkotlin.home={kotlin}", "-cp", str(libs / "*"),
                "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
    compiler_version = subprocess.run([*compiler, "-version"], capture_output=True, check=True, timeout=30)
    compiler_version = (compiler_version.stdout + compiler_version.stderr).decode().strip()
    runtime = subprocess.run([java, "-version"], capture_output=True, check=True, timeout=30)
    runtime = (runtime.stdout + runtime.stderr).decode().splitlines()[0]
    if f"kotlinc-jvm {KOTLIN} " not in compiler_version or '"17.' not in runtime:
        raise RuntimeError(f"Expected Kotlin {KOTLIN} and JDK 17, got {compiler_version} and {runtime}")

    with tempfile.TemporaryDirectory(prefix="abc-rfc8439-kotlin-") as directory:
        work = Path(directory)
        artifacts = {}
        reports = {}
        jars = {}

        def compile_jar(artifact, sources, dependencies):
            run([*compiler, "-Werror", "-jvm-target", "17", "-no-stdlib", "-no-reflect",
                 "-classpath", os.pathsep.join(map(str, [stdlib, *dependencies])), "-d", str(artifact),
                 *map(str, sources)])

        for profile in built:
            method, name, _ = resolver[profile]
            jar = work / f"abc-{name.lower()}-kotlin.jar"
            source = CRYPTO / method / f"impl/kotlin/src/{name}.kt"
            compile_jar(jar, [source], jars.values() if profile == "aead" else [])
            jars[profile] = jar
            artifacts[profile] = {"source_sha256": fingerprint(source), "jar_sha256": fingerprint(jar)}

        for profile in tested:
            method, _, _ = resolver[profile]
            test = CRYPTO / method / "impl/kotlin/tests/Checks.kt"
            consumer = work / f"{profile}-consumer.jar"
            compile_jar(consumer, [HERE / "tests/Support.kt", test], jars.values())
            fixtures = work / f"{profile}.tsv"
            if profile == "chacha20":
                cases = harness["chacha_cases"]()
                fields = ("key", "nonce", "counter", "message")
            elif profile == "poly1305":
                cases, direct = harness["poly_cases"](oracle)
                fields = ("key", "message", "expected")
                if not openssl:
                    raise ValueError("Set ABC_OPENSSL or --openssl to a direct OpenSSL executable.")
            else:
                cases = harness["aead_cases"]()
                fields = ("key", "nonce", "aad", "message")
            fixtures.write_text("".join("\t".join(str(case[field]) for field in fields) + "\n"
                                        for case in cases), encoding="utf-8")
            classpath = os.pathsep.join(map(str, [stdlib, *jars.values(), consumer]))
            output_lines = run([java, "-cp", classpath, MAIN, str(fixtures)]).decode().splitlines()
            results = []
            stats = {}
            for line in output_lines:
                key, value = line.split("=", 1)
                if key == "result":
                    results.append(value)
                else:
                    stats[key] = value
            expected_kat = {"chacha20": "2", "poly1305": "8", "aead": "1"}[profile]
            if stats.get("rfc") != expected_kat or stats.get("boundaries") != "passed" or len(results) != len(cases):
                raise ValueError(f"Incomplete Kotlin consumer result: {stats}")

            if profile == "poly1305":
                if results != [case["expected"] for case in cases]:
                    raise ValueError("Kotlin Poly1305 differs from the independent polynomial oracle")
                openssl_version = run([openssl, "version"]).decode().strip()
                for i, (key, message) in enumerate(direct, start=8):
                    observed = run([openssl, "mac", "-macopt", f"hexkey:{key.hex()}", "POLY1305"],
                                   input=message).decode().strip().lower()
                    if results[i] != observed:
                        raise ValueError("Kotlin Poly1305 differs from OpenSSL EVP-MAC")
                result = {"polynomial_cases": len(cases) - 8, "openssl_cases": len(direct),
                          "openssl_version": openssl_version}
            else:
                if profile == "chacha20":
                    expected = [{"ciphertext": value} for value in results]
                else:
                    expected = [dict(zip(("ciphertext", "tag"), value.split("\t"))) for value in results]
                    cases = [{**case, **wire} for case, wire in zip(cases, expected)]
                response = oracle["node_cases"](cases)
                if response["output"] != expected:
                    raise ValueError(f"Kotlin {profile} differs from OpenSSL")
                result = {"openssl_cases": len(cases), "openssl_version": response["version"]}
            reports[profile] = {**result, "rfc_known": int(expected_kat), "api_boundary_checks": "passed",
                                "consumer_sha256": fingerprint(test)}

        if output:
            output.mkdir(parents=True, exist_ok=True)
            for jar in jars.values():
                shutil.copy2(jar, output)
        return {"status": "passed", "compiler": compiler_version, "runtime": runtime,
                "stdlib_sha256": fingerprint(stdlib), "packages": artifacts, "results": reports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=["chacha20", "poly1305", "aead", "all"])
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--kotlin-home", type=Path, default=os.environ.get("ABC_KOTLIN_HOME"))
    parser.add_argument("--openssl", default=os.environ.get("ABC_OPENSSL") or shutil.which("openssl"))
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    if options.kotlin_home is None:
        parser.error("Set ABC_KOTLIN_HOME or pass --kotlin-home.")
    executable = "java.exe" if os.name == "nt" else "java"
    java = str(options.jdk.resolve() / "bin" / executable) if options.jdk else executable
    print(json.dumps(check(java, options.kotlin_home.resolve(), options.openssl,
                           options.profile, options.output), indent=2))


if __name__ == "__main__":
    main()
