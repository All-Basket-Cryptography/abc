"""Build the managed RFC 8439 profiles and run offline NuGet consumers."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import runpy
import shutil
import subprocess
import tempfile
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
CRYPTO = HERE.parents[3]
SDK = "10.0.404"
VERSION = "0.1.0"
PROFILES = {
    "chacha20": ("cipher/chacha20", "ChaCha20", "ChaCha20Cipher.cs"),
    "poly1305": ("mac/poly1305", "Poly1305", "Poly1305Mac.cs"),
    "aead": ("aead/chacha20-poly1305", "ChaCha20Poly1305", "ChaCha20Poly1305Aead.cs"),
}
C_ORACLE = CRYPTO / "aead/chacha20-poly1305/impl/c/check.py"
SUPPORT = HERE / "tests/TestSupport.cs"


def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}\n"
                           f"{result.stdout.decode(errors='replace')}{result.stderr.decode(errors='replace')}")
    return result.stdout


def chacha_cases():
    rng = random.Random(843920)
    sizes = [0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257, 64]
    cases = []
    for i in range(144):
        width = sizes[i] if i < len(sizes) else rng.randrange(1153)
        counter = (1 << 32) - 1 if i == len(sizes) - 1 else rng.randrange(1 << 24)
        cases.append(dict(mode="chacha20", key=rng.randbytes(32).hex(), nonce=rng.randbytes(12).hex(),
                          counter=counter, message=rng.randbytes(width).hex()))
    return cases


def aead_cases():
    rng = random.Random(8439)
    boundaries = [0, 1, 15, 16, 17, 63, 64, 65]
    widths = [(n, a) for n in boundaries for a in boundaries]
    widths += [(rng.randrange(1025), rng.randrange(145)) for _ in range(174 - len(widths))]
    return [dict(mode="aead", key=rng.randbytes(32).hex(), nonce=rng.randbytes(12).hex(),
                 aad=rng.randbytes(a).hex(), message=rng.randbytes(n).hex()) for n, a in widths]


def poly_cases(oracle):
    rng = random.Random(84391305)
    rfc = oracle["poly_cases"]()
    widths = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257]
    widths += [rng.randrange(385) for _ in range(512 - len(widths))]
    differential = [(rng.randbytes(32), rng.randbytes(n)) for n in widths]
    fixtures = [dict(key=key.hex(), message=message.hex(), expected=tag.hex())
                for key, message, tag in rfc]
    fixtures += [dict(key=key.hex(), message=message.hex(),
                      expected=oracle["poly_oracle"](key, message).hex()) for key, message in differential]
    return fixtures, differential[:32]


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(dotnet, openssl, selected, output, benchmark):
    oracle = runpy.run_path(str(C_ORACLE))
    tested = list(PROFILES) if selected == "all" else [selected]
    built = list(PROFILES) if selected in ("all", "aead") else tested
    with tempfile.TemporaryDirectory(prefix="abc-rfc8439-csharp-") as directory:
        work = Path(directory)
        feed = work / "feed"
        feed.mkdir()
        config = work / "NuGet.Config"
        config.write_text("<configuration><packageSources><clear /></packageSources></configuration>\n",
                          encoding="utf-8")
        (work / "global.json").write_text(json.dumps({"sdk": {"version": SDK, "rollForward": "disable"}}),
                                         encoding="utf-8")
        env = {**os.environ, "DOTNET_CLI_HOME": str(work), "DOTNET_NOLOGO": "1",
               "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "NUGET_PACKAGES": str(work / "packages"),
               "DOTNET_CLI_USE_MSBUILD_SERVER": "0", "MSBUILDDISABLENODEREUSE": "1",
               "UseSharedCompilation": "false"}

        def sdk(*args):
            return run([dotnet, *args], cwd=work, env=env)

        found = sdk("--version").decode().strip()
        if found != SDK:
            raise ValueError(f"Expected .NET SDK {SDK}, got {found}")

        def copy(file):
            destination = work / file.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, destination)
            return destination

        packages = {}
        for profile in built:
            algorithm, name, source = PROFILES[profile]
            leaf = CRYPTO / algorithm / "impl/csharp"
            copy(leaf / source)
            package_name = f"Abc.Cryptography.{name}"
            project = copy(leaf / f"{package_name}.csproj")
            sdk("restore", str(project), "--configfile", str(config), "--source", str(feed))
            sdk("pack", str(project), "--no-restore", "--configuration", "Release", "--output", str(feed))
            package = feed / f"{package_name}.{VERSION}.nupkg"
            with ZipFile(package) as archive:
                files = [name for name in archive.namelist() if name.endswith((".dll", ".so", ".dylib"))]
                if files != [f"lib/net10.0/{package_name}.dll"]:
                    raise ValueError(f"Unexpected package binaries: {files}")
            packages[profile] = {"source_sha256": fingerprint(leaf / source),
                                 "package_sha256": fingerprint(package)}

        copy(SUPPORT)
        results = {}
        for profile in tested:
            algorithm, name, _ = PROFILES[profile]
            tests = CRYPTO / algorithm / "impl/csharp/tests"
            copy(tests / "Program.cs")
            consumer = copy(tests / f"{name}.Tests.csproj")
            sdk("restore", str(consumer), "--configfile", str(config), "--source", str(feed))
            binary_dir = work / f"binary-{profile}"
            sdk("build", str(consumer), "--no-restore", "--configuration", "Release", "--output", str(binary_dir))
            executable = str(binary_dir / f"{name}.Tests.dll")
            if profile == "chacha20":
                fixtures = chacha_cases()
            elif profile == "poly1305":
                fixtures, direct_cases = poly_cases(oracle)
                if not openssl:
                    raise ValueError("Set ABC_OPENSSL or --openssl to a direct OpenSSL executable.")
            else:
                fixtures = aead_cases()
            inputs = work / f"{profile}.json"
            inputs.write_text(json.dumps(fixtures), encoding="utf-8")
            observed = json.loads(sdk(executable, str(inputs)))
            if len(observed["outputs"]) != len(fixtures):
                raise ValueError(f"Incomplete result from the {profile} consumer")

            if profile == "poly1305":
                expected = [item["expected"] for item in fixtures]
                if observed["outputs"] != expected:
                    raise ValueError("Poly1305 differs from the known-answer or expanded polynomial")
                provider_version = run([openssl, "version"]).decode().strip()
                for i, (key, message) in enumerate(direct_cases, start=8):
                    tag = run([openssl, "mac", "-macopt", f"hexkey:{key.hex()}", "POLY1305"],
                              input=message).decode().strip().lower()
                    if observed["outputs"][i] != tag:
                        raise ValueError("Poly1305 differs from OpenSSL EVP-MAC")
                results[profile] = {"rfc_known": 8, "polynomial_cases": len(fixtures) - 8,
                                    "openssl_cases": len(direct_cases), "openssl_version": provider_version}
            else:
                if profile == "aead":
                    fixtures = [{**fixture, **response} for fixture, response in zip(fixtures, observed["outputs"])]
                reply = oracle["node_cases"](fixtures)
                if observed["outputs"] != reply["output"]:
                    raise ValueError(f"{profile} differs from OpenSSL")
                results[profile] = {"rfc_known": observed["rfcKnown"], "openssl_cases": len(fixtures),
                                    "openssl_version": reply["version"]}
                if profile == "aead" and benchmark:
                    results[profile]["benchmark"] = json.loads(sdk(executable, "--benchmark"))
            results[profile]["api_boundary_checks"] = observed["boundaries"]
            results[profile]["consumer_sha256"] = fingerprint(tests / "Program.cs")

        if output:
            output.mkdir(parents=True, exist_ok=True)
            for package in feed.glob("*.nupkg"):
                shutil.copy2(package, output)
        return {"status": "passed", "sdk": SDK, "packages": packages, "results": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=[*PROFILES, "all"])
    parser.add_argument("--dotnet", default=os.environ.get("ABC_DOTNET", "dotnet"))
    parser.add_argument("--openssl", default=os.environ.get("ABC_OPENSSL") or shutil.which("openssl"))
    parser.add_argument("--output", type=Path, help="retain the checked offline NuGet packages")
    parser.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    print(json.dumps(check(args.dotnet, args.openssl, args.profile, args.output, args.benchmark), indent=2))


if __name__ == "__main__":
    main()
