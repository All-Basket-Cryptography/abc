"""Exercise either AES C# NuGet package from a separate offline consumer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
from statistics import median
import subprocess
from tempfile import TemporaryDirectory
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
REFERENCE = runpy.run_path(str(HERE.parent / "java/check.py"))["reference"]
PROFILES = {"aes256": (HERE, "Aes256", 514),
            "aes256-gcm": (HERE.parents[3] / "aead/aes256-gcm/impl/csharp", "Aes256Gcm", 274)}


def benchmark_report(observed):
    reports = observed if isinstance(observed, list) else [observed]
    for report in reports:
        for label in tuple(report):
            result = report[label]
            if isinstance(result, dict):
                result["medianNs"] = median(result["samplesNs"])
                result["medianBytesPerOperation"] = median(result["allocatedBytes"]) / report["iterations"]
    return {"host_cpu": platform.processor(), "measurements": reports}


def check(profile, dotnet, measured, package_output):
    leaf, name, cases = PROFILES[profile]
    package_name = "Abc.Cryptography." + name
    source = leaf / f"{name}Cipher.cs"
    version = json.loads((leaf / "global.json").read_text(encoding="utf-8"))["sdk"]["version"]
    oracle = REFERENCE(profile)
    with TemporaryDirectory(prefix="abc-aes-csharp-") as directory:
        work = Path(directory)
        for file in (f"{package_name}.csproj", source.name, "global.json", "README.md"):
            shutil.copy2(leaf / file, work / file)
        consumer_dir, feed = work / "consumer", work / "feed"
        shutil.copytree(leaf / "tests", consumer_dir, ignore=shutil.ignore_patterns("bin", "obj"))
        feed.mkdir()
        config = work / "NuGet.Config"
        config.write_text("<configuration><packageSources><clear /></packageSources></configuration>\n", encoding="utf-8")
        env = {**os.environ, "DOTNET_CLI_HOME": str(work), "DOTNET_NOLOGO": "1",
               "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "NUGET_PACKAGES": str(work / "packages")}

        def run(*arguments, input=None):
            result = subprocess.run([dotnet, *arguments], input=input, cwd=work, env=env, text=True, encoding="utf-8",
                                    capture_output=True, timeout=120)
            if result.returncode:
                raise RuntimeError(f"dotnet {arguments[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
            return result.stdout.strip()

        observed_sdk = run("--version")
        if observed_sdk != version:
            raise ValueError(f"Expected pinned .NET SDK {version}, got {observed_sdk}")
        project = work / f"{package_name}.csproj"
        run("restore", str(project), "--configfile", str(config), "--source", str(feed))
        run("pack", str(project), "--no-restore", "--configuration", "Release", "--output", str(feed))
        package = feed / f"{package_name}.0.1.0.nupkg"
        with ZipFile(package) as archive:
            binaries = [file for file in archive.namelist() if file.endswith((".dll", ".so", ".dylib"))]
            if binaries != [f"lib/net10.0/{package_name}.dll"] or "README.md" not in archive.namelist():
                raise ValueError(f"Unexpected package contents: {archive.namelist()}")

        consumer, output = consumer_dir / f"{name}.Tests.csproj", work / "binary"
        run("restore", str(consumer), "--configfile", str(config), "--source", str(feed))
        run("build", str(consumer), "--no-restore", "--configuration", "Release", "--output", str(output))
        executable = output / f"{name}.Tests.dll"
        results = json.loads(run(str(executable), input="\n".join(oracle["output"]) + "\n"))
        if results["cases"] != cases or (profile == "aes256-gcm" and results["authFailures"] != 89):
            raise ValueError(f"Incomplete conformance evidence: {results}")
        report = {"status": "passed", "profile": profile, "sdk": version, "platform": platform.platform(),
                  "oracle": {key: oracle[key] for key in ("node", "openssl")},
                  "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "artifact_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                  "results": {"known_answers": 2, "openssl_cases": cases - 2, **results}}
        if measured:
            report["benchmark"] = benchmark_report(json.loads(run(str(executable), "--benchmark")))
        if package_output:
            package_output.mkdir(parents=True, exist_ok=True)
            shutil.copy2(package, package_output / package.name)
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=tuple(PROFILES))
    parser.add_argument("--dotnet", default=os.environ.get("ABC_DOTNET", "dotnet"), help="path to the pinned .NET SDK")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--output", type=Path, help="directory for the verified offline NuGet package")
    args = parser.parse_args()
    check(args.profile, args.dotnet, args.benchmark, args.output)
