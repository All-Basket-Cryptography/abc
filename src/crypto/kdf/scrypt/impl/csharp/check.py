"""Pack managed scrypt and compare a separate offline NuGet consumer with OpenSSL."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import ssl
import subprocess
import tempfile
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
FIXTURE_SOURCE = HERE.parent / "java/check.py"
MODULES = (
    ("hash/sha256", "Abc.Cryptography.Sha256", "0.1.0"),
    ("mac/hmac-sha256", "Abc.Cryptography.HmacSha256", "1.0.0"),
    ("kdf/pbkdf2-hmac-sha256", "Abc.Cryptography.Pbkdf2Sha256", "1.0.0"),
    ("kdf/scrypt", "Abc.Cryptography.Scrypt", "0.1.0"),
)
CONSUMER = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
    <Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Abc.Cryptography.Scrypt" Version="0.1.0" />
  </ItemGroup>
</Project>
"""


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(dotnet, work):
    test = HERE / "tests/Program.cs"
    pin = HERE / "global.json"
    shutil.copyfile(pin, work / pin.name)
    version = json.loads(pin.read_text(encoding="utf-8"))["sdk"]["version"]
    config = work / "NuGet.Config"
    config.write_text("<configuration><packageSources><clear/></packageSources></configuration>\n",
                      encoding="utf-8")
    feed = work / "feed"
    feed.mkdir()
    environment = {**os.environ, "DOTNET_CLI_HOME": str(work), "DOTNET_NOLOGO": "1",
                   "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "NUGET_PACKAGES": str(work / "packages"),
                   "MSBUILDDISABLENODEREUSE": "1", "DOTNET_CLI_USE_MSBUILD_SERVER": "0"}

    def run(*args, **kwargs):
        command = [dotnet, *map(str, args)]
        result = subprocess.run(command, cwd=work, env=environment, text=True, encoding="utf-8",
                                capture_output=True, timeout=100, **kwargs)
        if result.returncode:
            raise RuntimeError(f"{' '.join(command)} failed\n{result.stdout}{result.stderr}")
        return result.stdout.strip()

    actual = run("--version")
    if actual != version:
        raise ValueError(f"Expected .NET SDK {version}, got {actual}")
    build_flags = ("--disable-build-servers", "-m:1")
    copied = []
    sources = {pin.relative_to(CRYPTO).as_posix(): fingerprint(pin),
               test.relative_to(CRYPTO).as_posix(): fingerprint(test)}
    for algorithm, assembly, package_version in MODULES:
        module = Path(algorithm) / "impl/csharp"
        original, destination = CRYPTO / module, work / module
        destination.mkdir(parents=True)
        for source in sorted(original.glob("*.cs*")):
            shutil.copyfile(source, destination / source.name)
            sources[source.relative_to(CRYPTO).as_posix()] = fingerprint(source)
        copied.append((destination / f"{assembly}.csproj", assembly, package_version))
    artifacts = []
    for project, assembly, package_version in copied:
        run("restore", project, "--configfile", config, "--source", feed, *build_flags)
        run("pack", project, "--no-restore", "-c", "Release", "-o", feed, *build_flags)
        artifact = feed / f"{assembly}.{package_version}.nupkg"
        with ZipFile(artifact) as package:
            binaries = sorted(name for name in package.namelist() if name.endswith((".dll", ".so", ".dylib")))
            if binaries != [f"lib/net10.0/{assembly}.dll"]:
                raise ValueError(f"Unexpected package binaries for {assembly}: {binaries}")
        artifacts.append(artifact)

    consumer = work / "consumer"
    consumer.mkdir()
    shutil.copyfile(test, consumer / test.name)
    project = consumer / "Consumer.csproj"
    project.write_text(CONSUMER, encoding="utf-8")
    run("restore", project, "--configfile", config, "--source", feed, *build_flags)
    asset_file = consumer / "obj/project.assets.json"
    packages = set(json.loads(asset_file.read_text(encoding="utf-8"))["libraries"])
    if packages != {f"{assembly}/{version}" for _, assembly, version in MODULES}:
        raise ValueError(f"Unexpected package dependency closure: {packages}")
    binary = work / "bin"
    run("build", project, "--no-restore", "-c", "Release", "-o", binary, *build_flags)
    fixtures = runpy.run_path(str(FIXTURE_SOURCE))
    rows = list(fixtures["fixtures"]())
    wire = "".join(f"{pw.hex()}:{salt.hex()}:{n}:{r}:{p}:{expected}\n"
                   for pw, salt, n, r, p, expected in rows)
    observed = run(binary / "Consumer.dll", input=wire)
    checks = dict(line.split("=", 1) for line in observed.splitlines())
    if checks != {"cases": str(len(rows)), "one_byte_under_budget_rejections": str(len(rows)),
                  "malformed_parameters_rejected": "11"}:
        raise ValueError(f"Unexpected consumer counts: {checks}")
    return artifacts, {
        "status": "passed",
        "dotnet": version,
        "runtimes": run("--list-runtimes").splitlines(),
        "python": platform.python_version(),
        "openssl": ssl.OPENSSL_VERSION,
        "checks": {**checks, "rfc_known_answers": len(fixtures["RFC"])},
        "source_sha256": sources,
        "artifact_sha256": {path.name: fingerprint(path) for path in artifacts},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default=os.environ.get("ABC_DOTNET") or "dotnet")
    parser.add_argument("--output", type=Path, help="retain the tested local feed and receipt")
    options = parser.parse_args()
    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-csharp-scrypt-", dir=temporary_root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(temporary_root):
            raise ValueError("Temporary work directory is outside its established root")
        artifacts, report = check(options.dotnet, work)
        if options.output:
            output = options.output.resolve()
            output.mkdir(parents=True, exist_ok=True)
            for path in artifacts:
                shutil.copyfile(path, output / path.name)
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
