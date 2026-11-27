"""Package or compile the ABC .NET 10 SDK in an isolated build directory."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
from tempfile import TemporaryDirectory
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PACKAGE = "Abc.Cryptography.Research.0.1.0.nupkg"


def call(argv, cwd, env, timeout=180):
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError((result.stdout + result.stderr).strip())
    return result.stdout.strip()


def build(dotnet, output):
    executable = shutil.which(dotnet)
    if not executable:
        raise ValueError(".NET 10 SDK executable was not found")
    dotnet = Path(executable).resolve()
    with TemporaryDirectory(prefix="abc-dotnet-") as directory:
        stage = Path(directory)
        project = stage / "sdk"
        shutil.copytree(HERE, project, ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"))
        offline = stage / "feed"
        offline.mkdir()
        config = stage / "NuGet.Config"
        config.write_text("<?xml version='1.0'?><configuration><packageSources><clear /></packageSources></configuration>\n", encoding="utf-8")
        env = {**os.environ, "DOTNET_CLI_HOME": str(stage), "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1",
               "NUGET_PACKAGES": str(stage / "packages"), "DOTNET_ADD_GLOBAL_TOOLS_TO_PATH": "0"}
        version = call([dotnet, "--version"], stage, env)
        if not version.startswith("10.0."):
            raise ValueError(f"Expected .NET SDK 10.0, got {version}")
        package_project = project / "Abc.Cryptography.Research.csproj"
        call([dotnet, "restore", package_project, "--configfile", config, "--source", offline], stage, env)
        if output is None:
            call([dotnet, "build", package_project, "--no-restore", "--configuration", "Release"], stage, env)
            return {"sdk": version, "source_check": "passed"}
        if os.name != "nt" or platform.machine().lower() not in {"amd64", "x86_64"}:
            raise ValueError(".NET package qualification requires Windows x64")
        native = stage / "native"
        call(["cargo", "+1.92.0", "build", "--manifest-path", ROOT / "build/rust/Cargo.toml", "--locked", "--offline", "--release",
              "-p", "abc-c-ffi", "--target-dir", native], ROOT, env)
        library = native / "release/abc_crypto.dll"
        call([dotnet, "pack", package_project, "--no-restore", "--configuration", "Release", "--output", offline,
              f"-p:AbcNativeLibrary={library}"], stage, env)
        archive = offline / PACKAGE
        with ZipFile(archive) as package:
            required = {"lib/net10.0/Abc.Cryptography.Research.dll", "runtimes/win-x64/native/abc_crypto.dll"}
            if not required <= set(package.namelist()):
                raise ValueError("NuGet package is missing its managed or native library")
        consumer = stage / "consumer"
        shutil.copytree(HERE / "consumer", consumer)
        call([dotnet, "restore", "--configfile", config, "--source", offline], consumer, env)
        result = call([dotnet, "run", "--no-restore", "--configuration", "Release"], consumer, env)
        if not result.endswith("External .NET SHA-256 consumer passed"):
            raise ValueError("External .NET consumer did not report success")
        output.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(archive, output / PACKAGE)
        report = {"profile": "research", "sdk": version, "target": "win-x64", "artifact": PACKAGE,
                  "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "consumer": "passed"}
        (output / "dotnet-conformance.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default=os.environ.get("ABC_DOTNET", "dotnet"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--check-source", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args.dotnet, args.output), indent=2))
