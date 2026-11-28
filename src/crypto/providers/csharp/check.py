"""Verify independently packed C# SDKs from a local NuGet feed."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import tomllib
from urllib.request import urlopen
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[1]
PROFILES = {
    "argon2id": ("kdf", "Argon2id"),
    "ecdsa-p256-sha256": ("signature", "EcdsaP256Sha256"),
    "x25519": ("agreement", "X25519"),
    "ed25519": ("signature", "Ed25519"),
    "ml-kem-768": ("agreement", "MlKem768"),
    "ml-dsa-65": ("signature", "MlDsa65"),
}
PIN = tomllib.loads((HERE / "provider.toml").read_text(encoding="utf-8"))
BC_FILE = f'{PIN["package"]}.{PIN["version"]}.nupkg'


def digest(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def run(command, **kwargs):
    result = subprocess.run(command, text=True, encoding="utf-8", capture_output=True,
                            timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed ({result.returncode})\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def provider_archive(options, destination):
    if options.bc_nupkg:
        shutil.copyfile(options.bc_nupkg.resolve(), destination)
    else:
        package = PIN["package"].lower()
        version = PIN["version"]
        url = f"https://api.nuget.org/v3-flatcontainer/{package}/{version}/{package}.{version}.nupkg"
        with urlopen(url, timeout=45) as source:
            content = source.read(PIN["size"] + 1)
        if len(content) != PIN["size"]:
            raise ValueError("Unexpected provider archive size")
        destination.write_bytes(content)
    if destination.stat().st_size != PIN["size"] or digest(destination) != PIN["sha256"]:
        raise ValueError("Bouncy Castle package did not match the pinned archive")


def openssl_library(options):
    if options.libcrypto:
        return options.libcrypto.resolve()
    override = os.environ.get("ABC_OPENSSL_LIBRARY")
    if override:
        return Path(override).resolve()
    if os.name != "nt":
        locations = run(["ldconfig", "-p"]).splitlines()
        for line in locations:
            if line.strip().startswith("libcrypto.so.3 ") and " => " in line:
                return Path(line.rsplit(" => ", 1)[1]).resolve()
    raise ValueError("Provide an absolute OpenSSL 3.5+ library path for Ed25519")


def fixtures(profile_root, profile, invoke):
    if profile != "ml-kem-768":
        sys.path.insert(0, str(CRYPTO / "kdf/argon2id/impl/java"))
        base = runpy.run_path(str(profile_root / "impl/java/check.py"))
        if profile in ("argon2id", "ecdsa-p256-sha256"):
            return base["verify"](invoke)
        if profile == "ml-dsa-65":
            evidence = base["verify"](invoke)
            # The C# consumer verifies the expanded-key case's known signature
            # through the public SDK rather than importing that expanded key.
            del evidence["acvp_provider_expanded_sign"]
            return evidence
        oracle = base["reference"]()
        cases = oracle["output"]
        report = json.loads(invoke(wire="\n".join(cases) + "\n"))
        if report["cases"] != len(cases):
            raise ValueError("Unexpected independent provider case count")
        return {**report, "node": oracle["node"], "openssl": oracle["openssl"]}

    shared = runpy.run_path(str(profile_root / "spec/fixtures.py"))
    tests = []
    for case in shared["check_fixtures"]():
        if case["operation"] == "keygen":
            tests.append(f'keygen:{case["d"]}{case["z"]}:{case["ek"]}')
        elif case["operation"] == "reject_ek":
            tests.append(f'reject_ek:{case["ek"]}')
    if invoke("acvp", wire="\n".join(tests) + "\n") != str(len(tests)):
        raise ValueError("Unexpected SDK ACVP case count")

    seeds = [hashlib.sha512(f"ABC C# ML-KEM case {i}".encode("ascii")).hexdigest() for i in range(12)]
    rows = [line.split(":") for line in invoke("encapsulate", wire="\n".join(seeds) + "\n").splitlines()]
    cases = []
    for seed, (_, ciphertext, _) in zip(seeds, rows, strict=True):
        damaged = bytearray.fromhex(ciphertext)
        damaged[0] ^= 1
        cases.append({"seed": seed, "ciphertext": ciphertext, "damaged": damaged.hex()})
    oracle = json.loads(run(["node", str(profile_root / "impl/go/oracle.mjs")], input=json.dumps(cases)))
    verification = []
    for public_row, source, expected in zip(rows, cases, oracle, strict=True):
        public, _, shared_key = public_row
        if public != expected["public"] or shared_key != expected["decapsulated"]:
            raise ValueError("ML-KEM-768 public key or valid secret disagrees with OpenSSL")
        explicit = hashlib.shake_256(bytes.fromhex(source["seed"])[32:] +
                                    bytes.fromhex(source["damaged"])).hexdigest(32)
        if explicit != expected["rejected"] or explicit == shared_key:
            raise ValueError("Independent implicit-rejection oracle failed")
        verification.append(f'{source["seed"]}:{expected["ciphertext"]}:{expected["shared"]}')
        verification.append(f'{source["seed"]}:{source["damaged"]}:{explicit}')
    if invoke("decapsulate", wire="\n".join(verification) + "\n") != str(len(verification)):
        raise ValueError("Unexpected independent decapsulation case count")
    version = run(["node", "-p", "process.version + ' / OpenSSL ' + process.versions.openssl"])
    return {"acvp_sdk_cases": len(tests), "openssl_bidirectional": len(seeds),
            "implicit_rejection": len(seeds), "random_roundtrips": 4, "oracle": version}


def exercise(options, work):
    name = options.profile
    family, cls = PROFILES[name]
    profile = CRYPTO / family / name
    sdk = profile / "impl/csharp"
    product = f"Abc.Cryptography.{cls}"
    package = f"{product}.0.1.0.nupkg"
    feed = work / "feed"
    feed.mkdir()
    provider_archive(options, feed / BC_FILE)
    bc_assembly = f'{PIN["package"]}.dll'
    with ZipFile(feed / BC_FILE) as provider:
        provider_binary = hashlib.sha256(provider.read(f"lib/net6.0/{bc_assembly}")).hexdigest()
    shutil.copyfile(HERE / "global.json", work / "global.json")
    config = work / "NuGet.Config"
    config.write_text("<configuration><packageSources><clear/></packageSources></configuration>\n", encoding="utf-8")
    env = {**os.environ, "DOTNET_CLI_HOME": str(work), "DOTNET_NOLOGO": "1",
           "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "NUGET_PACKAGES": str(work / "packages"),
           "MSBUILDDISABLENODEREUSE": "1", "DOTNET_CLI_USE_MSBUILD_SERVER": "0"}
    report = {}
    if name == "ed25519":
        native = openssl_library(options)
        if not native.is_file():
            raise ValueError("OpenSSL libcrypto must name an existing file")
        env["ABC_OPENSSL_LIBRARY"] = str(native)
        report["libcrypto_sha256"] = digest(native)

    def dotnet(*args, **kwargs):
        return run([options.dotnet, *map(str, args)], cwd=work, env=env, **kwargs)

    version = dotnet("--version")
    pin_version = json.loads((HERE / "global.json").read_text(encoding="utf-8"))["sdk"]["version"]
    if version != pin_version:
        raise ValueError(f"Expected .NET SDK {pin_version}, got {version}")

    build_flags = ("--disable-build-servers", "-m:1")
    producer = work / "producer"
    producer.mkdir()
    source = sdk / f"{cls}.cs"
    project = sdk / f"{product}.csproj"
    for file in (source, project):
        shutil.copyfile(file, producer / file.name)
    dotnet("restore", producer / project.name, "--configfile", config, "--source", feed, *build_flags)
    dotnet("pack", producer / project.name, "--no-restore", "-c", "Release", "-o", feed, *build_flags)
    artifact = feed / package
    with ZipFile(artifact) as archive:
        binaries = [name for name in archive.namelist() if name.lower().endswith((".dll", ".so", ".dylib"))]
        if binaries != [f"lib/net10.0/{product}.dll"]:
            raise ValueError(f"Unexpected packaged binaries: {binaries}")
        report["dll_sha256"] = hashlib.sha256(archive.read(binaries[0])).hexdigest()

    consumer = work / "consumer"
    consumer.mkdir()
    testcase = sdk / "tests/Program.cs"
    shutil.copyfile(testcase, consumer / testcase.name)
    consumer_project = consumer / "Consumer.csproj"
    consumer_project.write_text(f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>
  <ItemGroup><PackageReference Include="{product}" Version="[0.1.0]" /></ItemGroup>
</Project>
""", encoding="utf-8")
    dotnet("restore", consumer_project, "--configfile", config, "--source", feed, *build_flags)
    closure = set(json.loads((consumer / "obj/project.assets.json").read_text(encoding="utf-8"))["libraries"])
    if closure != {f'{PIN["package"]}/{PIN["version"]}', f"{product}/0.1.0"}:
        raise ValueError(f"Unexpected NuGet dependency closure: {closure}")
    binary = work / "bin"
    dotnet("build", consumer_project, "--no-restore", "-c", "Release", "-o", binary, *build_flags)
    if digest(binary / f"{product}.dll") != report["dll_sha256"] or digest(binary / bc_assembly) != provider_binary:
        raise ValueError("The consumer's SDK or provider binary differs from the restored archive")

    def invoke(*args, wire=""):
        return dotnet(binary / "Consumer.dll", *args, input=wire)

    runtime = [line.split(" [", 1)[0] for line in dotnet("--list-runtimes").splitlines()
               if line.startswith("Microsoft.NETCore.App ")]
    report.update({"status": "passed", "dotnet": version, "runtime": runtime, "provider": PIN,
                   "provider_dll_sha256": provider_binary, "profile": name,
                   "checks": fixtures(profile, name, invoke), "source_sha256": digest(source),
                   "test_sha256": digest(testcase), "artifact_sha256": digest(artifact)})
    return artifact, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--dotnet", default=os.environ.get("ABC_DOTNET") or "dotnet")
    parser.add_argument("--bc-nupkg", type=Path, default=os.environ.get("ABC_BC_NUGET"))
    parser.add_argument("--libcrypto", type=Path)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="abc-net-", dir=root) as directory:
        work = Path(directory).resolve()
        if not work.is_relative_to(root):
            raise ValueError("Unexpected temporary working path")
        artifact, report = exercise(options, work)
        if options.output:
            output = options.output.resolve()
            output.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(artifact, output / artifact.name)
            (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
