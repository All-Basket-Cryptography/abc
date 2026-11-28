"""Build separate Swift AES consumers and compare with NIST and OpenSSL vectors."""

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
REFERENCE = HERE.parent / "java/check.py"
PROFILES = {
    "aes256": ("cipher/aes256", "Aes256", 514),
    "aes256-gcm": ("aead/aes256-gcm", "Aes256Gcm", 274),
}


def run(*command):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=120)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def fingerprint(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def check(swift, selected, benchmark):
    version = run(swift, "--version")
    if "Apple Swift version 6.1.2 " not in version or "Target: arm64-apple-macosx" not in version:
        raise ValueError(f"Expected Apple Swift 6.1.2 for macOS arm64, got {version}")
    oracle = runpy.run_path(str(REFERENCE))["reference"]
    tested = list(PROFILES) if selected == "all" else [selected]
    results = {}
    with TemporaryDirectory(prefix="abc-swift-aes-consumer-") as directory:
        work = Path(directory)
        for profile in tested:
            path, name, count = PROFILES[profile]
            leaf = CRYPTO / path / "impl/swift"
            target = f"Abc{name}Swift"
            package = leaf / target
            consumer = work / f"{profile}-consumer"
            sources = consumer / "Sources/Consumer"
            sources.mkdir(parents=True)
            test = leaf / "tests/main.swift"
            shutil.copy2(test, sources)
            shutil.copy2(HERE / "tests/Support.swift", sources)
            (consumer / "Package.swift").write_text(f"""// swift-tools-version: 6.1
import PackageDescription
let package = Package(
    name: "Consumer",
    platforms: [.macOS(.v13)],
    dependencies: [.package(path: {json.dumps(package.as_posix())})],
    targets: [.executableTarget(name: "Consumer", dependencies: [
        .product(name: "{target}", package: "{target.lower()}"),
    ])]
)
""", encoding="utf-8")

            expected = oracle(profile)
            fixture = work / f"{profile}.txt"
            fixture.write_text("\n".join(expected["output"]) + "\n", encoding="utf-8")
            scratch = work / f"{profile}-scratch"
            command = (swift, "run", "--package-path", str(consumer), "--scratch-path", str(scratch),
                       "--configuration", "release", "-Xswiftc", "-warnings-as-errors", "Consumer")
            observed = dict(line.split("=", 1) for line in run(*command, str(fixture)).splitlines())
            if observed != ({"cases": str(count), "bounds": "passed", "auth_failures": "77"}
                            if profile == "aes256-gcm" else {"cases": str(count), "bounds": "passed"}):
                raise ValueError(f"Incomplete Swift {profile} checks: {observed}")
            source = package / "Sources" / target / f"{name}.swift"
            result = {"known_answers": 2, "openssl_cases": count - 2, **observed,
                      "oracle": {key: expected[key] for key in ("node", "openssl")},
                      "source_sha256": fingerprint(source), "consumer_sha256": fingerprint(test),
                      "fixture_sha256": fingerprint(fixture)}
            if benchmark:
                timings = dict(line.split("=", 1) for line in run(*command, "--benchmark").splitlines())
                result["benchmark"] = {key: float(value) if key.endswith("_ns") else int(value)
                                       for key, value in timings.items()}
                result["benchmark"]["payload_bytes"] = 4096 if profile == "aes256-gcm" else 16
                result["benchmark"]["aad_bytes"] = 16 if profile == "aes256-gcm" else 0
            results[profile] = result

    return {"status": "passed", "toolchain": version, "platform": platform.platform(),
            "machine": platform.machine(), "results": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=[*PROFILES, "all"])
    parser.add_argument("--swift", default="swift")
    parser.add_argument("--benchmark", action="store_true")
    args = parser.parse_args()
    print(json.dumps(check(args.swift, args.profile, args.benchmark), indent=2))


if __name__ == "__main__":
    main()
