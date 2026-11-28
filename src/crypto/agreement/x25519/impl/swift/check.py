"""Build independent SwiftPM curve consumers and compare with OpenSSL."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import runpy
import shutil
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
PROFILES = {
    "x25519": ("agreement/x25519", "X25519",
               {"openssl_cases": "196", "rfc_known": "6", "scalar_aliases": "32",
                "peer_aliases": "3", "low_order_rejections": "14", "bounds": "passed"}),
    "ed25519": ("signature/ed25519", "Ed25519",
                {"openssl_cases": "99", "rfc_known": "3", "invalid_points": "12", "bounds": "passed"}),
}


def run(*command):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=120)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def fingerprint(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def consumer_manifest(package, target):
    return f"""// swift-tools-version: 6.1
import PackageDescription
let package = Package(
    name: "Consumer",
    platforms: [.macOS(.v15)],
    dependencies: [.package(path: {json.dumps(package.as_posix())})],
    targets: [.executableTarget(name: "Consumer", dependencies: [
        .product(name: "{target}", package: "{target.lower()}"),
    ])]
)
"""


def check(swift, selected):
    version = run(swift, "--version")
    if "Apple Swift version 6.1.2 " not in version or "Target: arm64-apple-macosx" not in version:
        raise ValueError(f"Expected Apple Swift 6.1.2 for macOS arm64, got {version}")
    tested = list(PROFILES) if selected == "all" else [selected]
    results = {}
    with TemporaryDirectory(prefix="abc-swift-curves-consumer-") as directory:
        work = Path(directory)
        for profile in tested:
            path, name, want = PROFILES[profile]
            leaf = CRYPTO / path / "impl/swift"
            target = f"Abc{name}Swift"
            package = leaf / target
            consumer = work / f"{profile}-consumer"
            sources = consumer / "Sources/Consumer"
            sources.mkdir(parents=True)
            test = leaf / "tests/main.swift"
            shutil.copy2(test, sources)
            shutil.copy2(HERE / "tests/Support.swift", sources)
            (consumer / "Package.swift").write_text(consumer_manifest(package, target), encoding="utf-8")

            oracle = runpy.run_path(str(leaf.parent / "java/check.py"))["reference"]()
            fixture = work / f"{profile}.txt"
            fixture.write_text("\n".join(oracle["output"]) + "\n", encoding="utf-8")
            scratch = work / f"{profile}-scratch"
            command = (swift, "run", "--package-path", str(consumer), "--scratch-path", str(scratch),
                       "--configuration", "release", "-Xswiftc", "-warnings-as-errors", "Consumer")
            observed = dict(line.split("=", 1) for line in run(*command, str(fixture)).splitlines())
            if observed != want:
                raise ValueError(f"Incomplete Swift {profile} conformance evidence: {observed}")
            source = package / "Sources" / target / f"{name}.swift"
            provider = "Apple CryptoKit" if profile == "x25519" else "Apple CryptoKit and OpenSSL EVP"
            results[profile] = {"checks": observed, "provider": provider,
                                "oracle": {key: oracle[key] for key in ("node", "openssl")},
                                "source_sha256": fingerprint(source), "consumer_sha256": fingerprint(test),
                                "fixture_sha256": fingerprint(fixture)}

    return {"status": "passed", "toolchain": version, "platform": platform.platform(), "results": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=[*PROFILES, "all"])
    parser.add_argument("--swift", default="swift")
    args = parser.parse_args()
    print(json.dumps(check(args.swift, args.profile), indent=2))


if __name__ == "__main__":
    main()
