"""Pack standalone C# BLAKE2b and test an external consumer from an offline local feed."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import ssl
from statistics import median
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
PACKAGE = "Abc.Cryptography.Blake2b"
VERSION = "0.1.0"
SDK = json.loads((HERE / "global.json").read_text(encoding="utf-8"))["sdk"]["version"]
REFERENCE = runpy.run_path(str(HERE.parent / "cpp" / "check.py"))


def benchmark(dotnet_run, executable):
    report = json.loads(dotnet_run(str(executable), "--benchmark"))
    length, hashes = report["messageBytes"], report["hashesPerBatch"]
    message = bytes((37 * i + 11) & 0xff for i in range(256)) * (length // 256)
    for _ in range(4):
        REFERENCE["reference"](message, 64)
    openssl = []
    for _ in report["samples"]:
        start = perf_counter()
        for _ in range(hashes):
            REFERENCE["reference"](message, 64)
        openssl.append(hashes / (perf_counter() - start))
    return {**report, "nativeMedianMibPerSecond": median(report["samples"]),
            "opensslMedianMibPerSecond": median(openssl), "hostCpu": platform.processor()}


def check(dotnet, measured):
    with TemporaryDirectory(prefix="abc-blake2b-csharp-") as directory:
        work = Path(directory)
        for file in (f"{PACKAGE}.csproj", "Blake2bHasher.cs", "global.json", "README.md"):
            shutil.copy2(HERE / file, work / file)
        consumer_dir, feed = work / "consumer", work / "feed"
        shutil.copytree(HERE / "tests", consumer_dir, ignore=shutil.ignore_patterns("bin", "obj"))
        feed.mkdir()
        config = work / "NuGet.Config"
        config.write_text("<configuration><packageSources><clear /></packageSources></configuration>\n",
                          encoding="utf-8")
        env = {**os.environ, "DOTNET_CLI_HOME": str(work), "DOTNET_NOLOGO": "1",
               "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "NUGET_PACKAGES": str(work / "packages")}

        def dotnet_run(*args, input=None):
            result = subprocess.run([dotnet, *args], cwd=work, env=env, input=input, capture_output=True,
                                    text=True, encoding="utf-8", timeout=120)
            if result.returncode:
                raise RuntimeError(f"dotnet {args[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
            return result.stdout.strip()

        version = dotnet_run("--version")
        if version != SDK:
            raise ValueError(f"Expected .NET SDK {SDK}, got {version}")
        project = work / f"{PACKAGE}.csproj"
        dotnet_run("restore", str(project), "--configfile", str(config), "--source", str(feed))
        dotnet_run("pack", str(project), "--no-restore", "--configuration", "Release", "--output", str(feed))
        package = feed / f"{PACKAGE}.{VERSION}.nupkg"
        with ZipFile(package) as archive:
            binaries = [file for file in archive.namelist() if file.endswith((".dll", ".so", ".dylib"))]
            if binaries != [f"lib/net10.0/{PACKAGE}.dll"] or "README.md" not in archive.namelist():
                raise ValueError(f"Unexpected package contents: {archive.namelist()}")

        consumer = consumer_dir / "Blake2b.Tests.csproj"
        binaries = work / "consumer-bin"
        dotnet_run("restore", str(consumer), "--configfile", str(config), "--source", str(feed))
        dotnet_run("build", str(consumer), "--no-restore", "--configuration", "Release", "--output", str(binaries))
        executable = binaries / "Blake2b.Tests.dll"
        fixtures = "\n".join(REFERENCE["fixtures"]()) + "\n"
        report = {"status": "passed", "sdk": version, "platform": platform.platform(), "oracle": ssl.OPENSSL_VERSION,
                  "source_sha256": hashlib.sha256((HERE / "Blake2bHasher.cs").read_bytes()).hexdigest(),
                  "artifact_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                  "results": json.loads(dotnet_run(str(executable), input=fixtures))}
        if measured:
            report["benchmark"] = benchmark(dotnet_run, executable)
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default=os.environ.get("ABC_DOTNET", "dotnet"), help="path to the pinned .NET SDK")
    parser.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    check(args.dotnet, args.benchmark)
