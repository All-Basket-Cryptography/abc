"""Check native Keccak-based JVM JARs and .NET packages with isolated consumers."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
HASH_ROOT = HERE.parents[2]
CORE = "keccak-p1600"
ALGORITHMS = (CORE, "sha3-256", "shake256")
ASSEMBLIES = {
    CORE: "Abc.Cryptography.KeccakP1600",
    "sha3-256": "Abc.Cryptography.Sha3_256",
    "shake256": "Abc.Cryptography.Shake256",
}
RUNTIME_VERSION = "17"
KOTLIN_VERSION = "2.1.21"


def leaf(algorithm, language):
    return HASH_ROOT / algorithm / "impl" / language


def run(command, **kwargs):
    result = subprocess.run(command, text=True, encoding="utf-8", capture_output=True,
                            timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout.strip(), result.stderr.strip()


def source_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def executable(jdk, name):
    file = name + (".exe" if os.name == "nt" else "")
    return str(jdk.resolve() / "bin" / file) if jdk else file


def classpath(files):
    return os.pathsep.join(map(str, files))


def fixture_input(algorithm):
    if algorithm == CORE:
        return "", None
    fixture, _ = run(["node", str(HERE / "fixtures.mjs")])
    version, _ = run(["node", "-p", "process.version + ' / OpenSSL ' + process.versions.openssl"])
    return fixture + "\n", version


def compile_jvm(language, algorithm, options, work, fixtures):
    java = executable(options.jdk, "java")
    out, err = run([java, "-version"])
    version = out or err
    if not re.search(rf'version "{RUNTIME_VERSION}(?:\.|")', version):
        raise ValueError(f"Expected JDK {RUNTIME_VERSION}, got {version}")
    if language == "java":
        compiler = [executable(options.jdk, "javac"), "--release", RUNTIME_VERSION, "-Xlint:all", "-Werror"]
        jar = executable(options.jdk, "jar")
        stdlib = []

        def build(name, sources, dependencies):
            artifact = work / f"{name}.jar"
            classes = work / name
            classes.mkdir()
            class_args = ["-classpath", classpath(dependencies)] if dependencies else []
            run([*compiler, *class_args, "-d", str(classes), *map(str, sources)])
            run([jar, "--create", "--file", str(artifact), "--date", "2000-01-01T00:00:00Z",
                 "-C", str(classes), "."])
            return artifact
    else:
        if options.kotlin_home is None:
            raise ValueError("Select Kotlin 2.1.21 with --kotlin-home or ABC_KOTLIN_HOME")
        home = options.kotlin_home.resolve()
        library = home / "lib"
        stdlib = [library / "kotlin-stdlib.jar"]
        compiler = [java, f"-Dkotlin.home={home}", "-cp", str(library / "*"),
                    "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler"]
        out, err = run([*compiler, "-version"])
        kotlin_version = out or err
        if not re.search(rf"\bkotlinc-jvm {re.escape(KOTLIN_VERSION)}\b", kotlin_version):
            raise ValueError(f"Expected Kotlin {KOTLIN_VERSION}, got {kotlin_version}")
        version += "\n" + kotlin_version
        flags = ["-Xjdk-release=17", "-Werror", "-no-stdlib", "-no-reflect"]

        def build(name, sources, dependencies):
            artifact = work / f"{name}.jar"
            run([*compiler, *flags, "-classpath", classpath([*stdlib, *dependencies]),
                 "-d", str(artifact), *map(str, sources)])
            return artifact

    suffix = ".java" if language == "java" else ".kt"
    core_sources = sorted((leaf(CORE, language) / "src").rglob(f"*{suffix}"))
    core = build("abc-keccak-p1600", core_sources, [])
    artifacts = [core]
    source_files = list(core_sources)
    if algorithm != CORE:
        producer = sorted((leaf(algorithm, language) / "src").rglob(f"*{suffix}"))
        artifacts.append(build(f"abc-{algorithm}", producer, [core]))
        source_files.extend(producer)
    test = leaf(algorithm, language) / "tests" / f"Checks{suffix}"
    source_files.append(test)
    consumer = build("consumer", [test], artifacts)
    test_name = "Checks" if language == "java" else "ChecksKt"
    observed, _ = run([java, "-cp", classpath([*stdlib, *artifacts, consumer]), test_name],
                      cwd=work, input=fixtures)
    return version, source_files, artifacts, observed


def compile_csharp(algorithm, options, work, fixtures):
    dotnet = options.dotnet
    pin = leaf(CORE, "csharp") / "global.json"
    shutil.copyfile(pin, work / pin.name)
    version = json.loads(pin.read_text(encoding="utf-8"))["sdk"]["version"]
    config = work / "NuGet.Config"
    config.write_text("<configuration><packageSources><clear/></packageSources></configuration>\n", encoding="utf-8")
    feed = work / "feed"
    feed.mkdir()
    env = {**os.environ, "DOTNET_CLI_HOME": str(work), "DOTNET_NOLOGO": "1",
           "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "NUGET_PACKAGES": str(work / "packages")}

    def command(*args, **kwargs):
        return run([dotnet, *map(str, args)], cwd=work, env=env, **kwargs)[0]

    actual = command("--version")
    if actual != version:
        raise ValueError(f"Expected .NET SDK {version}, got {actual}")
    source_files = [pin]
    artifacts = []
    for profile in ([CORE] if algorithm == CORE else [CORE, algorithm]):
        original = leaf(profile, "csharp")
        copied = work / profile / "impl/csharp"
        copied.mkdir(parents=True)
        for source in sorted(original.glob("*.cs*")):
            shutil.copyfile(source, copied / source.name)
            source_files.append(source)
        assembly = ASSEMBLIES[profile]
        project = copied / f"{assembly}.csproj"
        command("restore", project, "--configfile", config, "--source", feed)
        command("pack", project, "--no-restore", "-c", "Release", "-o", feed)
        artifact = feed / f"{assembly}.0.1.0.nupkg"
        with ZipFile(artifact) as package:
            binaries = sorted(name for name in package.namelist() if name.endswith((".dll", ".so", ".dylib")))
            if binaries != [f"lib/net10.0/{assembly}.dll"]:
                raise ValueError(f"Unexpected package binaries for {assembly}: {binaries}")
        artifacts.append(artifact)

    consumer = work / "consumer"
    consumer.mkdir()
    test = leaf(algorithm, "csharp") / "tests/Program.cs"
    source_files.append(test)
    shutil.copyfile(test, consumer / test.name)
    project = consumer / "Consumer.csproj"
    project.write_text(f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
    <Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="{ASSEMBLIES[algorithm]}" Version="0.1.0" />
  </ItemGroup>
</Project>\n""", encoding="utf-8")
    command("restore", project, "--configfile", config, "--source", feed)
    binary = work / "bin"
    command("build", project, "--no-restore", "-c", "Release", "-o", binary)
    observed = command(binary / "Consumer.dll", input=fixtures)
    return version, source_files, artifacts, observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("java", "kotlin", "csharp"), required=True)
    parser.add_argument("--algorithm", choices=ALGORITHMS, required=True)
    parser.add_argument("--jdk", type=Path, default=os.environ.get("ABC_JAVA_HOME"))
    parser.add_argument("--kotlin-home", type=Path, default=os.environ.get("ABC_KOTLIN_HOME"))
    parser.add_argument("--dotnet", default=os.environ.get("ABC_DOTNET") or "dotnet")
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    fixtures, provider = fixture_input(options.algorithm)
    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-keccak-", dir=temporary_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(temporary_root):
            raise ValueError("Temporary work directory is outside its established root")
        if options.language == "csharp":
            version, sources, artifacts, output = compile_csharp(options.algorithm, options, work, fixtures)
        else:
            version, sources, artifacts, output = compile_jvm(options.language, options.algorithm, options, work, fixtures)
        checks = dict(line.split("=", 1) for line in output.splitlines())
        if options.algorithm == CORE:
            if checks.get("permutation_lanes") != "25":
                raise ValueError("The consumer did not report testing 25 permutation lanes")
        else:
            cases = fixtures.splitlines()
            splits = sum(len(case.split(":", 1)[0]) // 2 + 1 for case in cases)
            if checks.get("cases") != str(len(cases)) or checks.get("splits") != str(splits):
                raise ValueError("The consumer did not report the requested case and split counts")
        report = {
            "status": "passed",
            "language": options.language,
            "algorithm": options.algorithm,
            "provider": provider,
            "version": version,
            "source_sha256": {path.relative_to(HASH_ROOT).as_posix(): source_hash(path) for path in sources},
            "artifact_sha256": {path.name: source_hash(path) for path in artifacts},
            "checks": checks,
        }
        if options.output:
            output = options.output.resolve()
            output.mkdir(parents=True, exist_ok=True)
            for artifact in artifacts:
                shutil.copyfile(artifact, output / artifact.name)
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
