"""Pack the native C# implementation and test a consumer with an offline NuGet feed."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
from tempfile import TemporaryDirectory
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
PACKAGE = "Abc.Cryptography.Sha512"
SDK = json.loads((HERE / "global.json").read_text(encoding="utf-8"))["sdk"]["version"]


def run(args, **kwargs):
    result = subprocess.run(args, text=True, encoding="utf-8", capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def check(dotnet, keep_package, benchmark):
    with TemporaryDirectory(prefix="abc-sha512-csharp-") as directory:
        work = Path(directory)
        for file in (f"{PACKAGE}.csproj", "Sha512Hasher.cs", "global.json"):
            shutil.copy2(HERE / file, work / file)
        tests = work / "consumer"
        tests.mkdir()
        for file in ("Program.cs", "Sha512.Tests.csproj"):
            shutil.copy2(HERE / "tests" / file, tests / file)
        feed = work / "feed"
        feed.mkdir()
        config = work / "NuGet.Config"
        config.write_text("<configuration><packageSources><clear /></packageSources></configuration>\n", encoding="utf-8")
        env = {**os.environ, "DOTNET_CLI_HOME": str(work), "DOTNET_NOLOGO": "1",
               "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "NUGET_PACKAGES": str(work / "packages")}

        def dotnet_run(*args):
            return run([dotnet, *args], cwd=work, env=env)

        version = dotnet_run("--version")
        if version != SDK:
            raise ValueError(f"Expected .NET SDK {SDK}, got {version}")
        project = work / f"{PACKAGE}.csproj"
        dotnet_run("restore", str(project), "--configfile", str(config), "--source", str(feed))
        dotnet_run("pack", str(project), "--no-restore", "--configuration", "Release", "--output", str(feed))
        package = feed / f"{PACKAGE}.0.1.0.nupkg"
        with ZipFile(package) as archive:
            binaries = [name for name in archive.namelist() if name.endswith((".dll", ".so", ".dylib"))]
            if binaries != [f"lib/net10.0/{PACKAGE}.dll"]:
                raise ValueError(f"Unexpected package binaries: {binaries}")
        consumer = tests / "Sha512.Tests.csproj"
        dotnet_run("restore", str(consumer), "--configfile", str(config), "--source", str(feed))
        bin_path = work / "consumer-bin"
        dotnet_run("build", str(consumer), "--no-restore", "--configuration", "Release", "--output", str(bin_path))
        executable = bin_path / "Sha512.Tests.dll"
        results = json.loads(dotnet_run(str(executable)))
        report = {
            "status": "passed", "sdk": version, "platform": platform.platform(),
            "source_sha256": hashlib.sha256((HERE / "Sha512Hasher.cs").read_bytes()).hexdigest(),
            "consumer_sha256": hashlib.sha256((HERE / "tests/Program.cs").read_bytes()).hexdigest(),
            "artifact_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
            "results": results,
        }
        if benchmark:
            measured = json.loads(dotnet_run(str(executable), "--benchmark"))
            measured["medianMibPerSecond"] = statistics.median(measured["samplesMibPerSecond"])
            measured["oracleMedianMibPerSecond"] = statistics.median(measured["oracleSamplesMibPerSecond"])
            measured["hostCpu"] = platform.processor()
            report["benchmark"] = measured
        if keep_package:
            keep_package.mkdir(parents=True, exist_ok=True)
            shutil.copy2(package, keep_package / package.name)
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default=os.environ.get("ABC_DOTNET", "dotnet"),
                        help="path to the pinned .NET SDK executable")
    parser.add_argument("--output", type=Path, help="retain the tested research package")
    parser.add_argument("--benchmark", action="store_true")
    options = parser.parse_args()
    print(json.dumps(check(options.dotnet, options.output, options.benchmark), indent=2))
