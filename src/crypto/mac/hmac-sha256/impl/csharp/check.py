"""Build and test managed HMAC-SHA-256 with the repository's pinned .NET SDK."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
SHA = CRYPTO / "hash/sha256/impl/csharp"
SDK = json.loads((SHA / "global.json").read_text(encoding="utf-8"))["sdk"]["version"]


def check(dotnet, files, test_project, sources):
    with TemporaryDirectory(prefix="abc-managed-check-") as directory:
        work = Path(directory)
        for source in files:
            target = work / source.relative_to(CRYPTO)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        shutil.copy2(SHA / "global.json", work / "global.json")
        config = work / "NuGet.Config"
        config.write_text("<configuration><packageSources><clear /></packageSources></configuration>\n",
                          encoding="utf-8")
        env = {**os.environ, "DOTNET_CLI_HOME": str(work), "DOTNET_NOLOGO": "1",
               "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "NUGET_PACKAGES": str(work / "packages")}

        def run(*args):
            result = subprocess.run([dotnet, *args], cwd=work, env=env, text=True,
                                    capture_output=True, timeout=90, check=False)
            if result.returncode:
                raise RuntimeError(f"dotnet {args[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
            return result.stdout.strip()

        sdk = run("--version")
        if sdk != SDK:
            raise ValueError(f"Expected .NET SDK {SDK}, got {sdk}")
        project = work / test_project.relative_to(CRYPTO)
        run("restore", str(project), "--configfile", str(config), "--disable-build-servers", "-m:1")
        run("build", str(project), "--no-restore", "--configuration", "Release", "--output",
            str(work / "out"), "--disable-build-servers", "-m:1")
        report = json.loads(run(str(work / "out" / f"{project.stem}.dll")))
    report["sdk"] = sdk
    report["sources_sha256"] = {
        source.relative_to(CRYPTO).as_posix(): hashlib.sha256(source.read_bytes()).hexdigest()
        for source in sources
    }
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default=os.environ.get("ABC_DOTNET", "dotnet"))
    options = parser.parse_args()
    sha_source = SHA / "Sha256Hasher.cs"
    source = HERE / "HmacSha256.cs"
    test = HERE / "tests/Program.cs"
    test_project = HERE / "tests/HmacSha256.Tests.csproj"
    files = [sha_source, SHA / "Abc.Cryptography.Sha256.csproj", source,
             HERE / "Abc.Cryptography.HmacSha256.csproj", test, test_project]
    print(json.dumps(check(options.dotnet, files, test_project, [source, sha_source, test]), indent=2))
