"""Check Swift RFC 8439 with independently built local SwiftPM consumers."""

import argparse
import json
import os
from pathlib import Path
import runpy
import shutil
import tempfile


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
CS_FIXTURES = HERE.parent / "csharp/check.py"


def check(swift, openssl, selected):
    harness = runpy.run_path(str(CS_FIXTURES))
    oracle = runpy.run_path(str(harness["C_ORACLE"]))
    profiles = harness["PROFILES"]
    tested = list(profiles) if selected == "all" else [selected]
    run = harness["run"]
    fingerprint = harness["fingerprint"]
    version = run([swift, "--version"]).decode().strip()
    if "Swift version 6.1.2 " not in version:
        raise RuntimeError(f"Expected Swift 6.1.2, got {version}")

    with tempfile.TemporaryDirectory(prefix="abc-rfc8439-swift-") as directory:
        work = Path(directory)
        report = {}
        for profile in tested:
            method, name, _ = profiles[profile]
            leaf = CRYPTO / method / "impl/swift"
            product = f"Abc{name}Swift"
            package = leaf / product
            consumer = work / f"{profile}-consumer"
            sources = consumer / "Sources/Consumer"
            sources.mkdir(parents=True)
            shutil.copy2(leaf / "tests/main.swift", sources)
            shutil.copy2(HERE / "tests/TestSupport.swift", sources)
            (consumer / "Package.swift").write_text(f"""// swift-tools-version: 6.1
import PackageDescription
let package = Package(
    name: "Consumer",
    platforms: [.macOS(.v13)],
    dependencies: [.package(path: {json.dumps(package.as_posix())})],
    targets: [.executableTarget(name: "Consumer", dependencies: [
        .product(name: "{product}", package: "{product.lower()}"),
    ])]
)
""", encoding="utf-8")

            fixtures = work / f"{profile}.tsv"
            if profile == "chacha20":
                cases = harness["chacha_cases"]()
                fields = ("key", "nonce", "counter", "message")
            elif profile == "poly1305":
                cases, direct = harness["poly_cases"](oracle)
                fields = ("key", "message", "expected")
                if not openssl:
                    raise ValueError("Set ABC_OPENSSL or --openssl to a direct OpenSSL executable.")
            else:
                cases = harness["aead_cases"]()
                fields = ("key", "nonce", "aad", "message")
            fixtures.write_text("".join("\t".join(str(case[field]) for field in fields) + "\n"
                                        for case in cases), encoding="utf-8")

            binary = work / f"{profile}-build"
            args = [swift, "run", "--package-path", str(consumer), "--scratch-path", str(binary),
                    "--configuration", "release", "-Xswiftc", "-warnings-as-errors",
                    "Consumer", str(fixtures)]
            output = run(args).decode().splitlines()
            results = []
            stats = {}
            for line in output:
                key, value = line.split("=", 1)
                if key == "result":
                    results.append(value)
                else:
                    stats[key] = value
            expected_kat = {"chacha20": "2", "poly1305": "8", "aead": "1"}[profile]
            if stats.get("rfc") != expected_kat or stats.get("boundaries") != "passed" or len(results) != len(cases):
                raise ValueError(f"Incomplete Swift consumer result: {stats}")

            if profile == "poly1305":
                if results != [case["expected"] for case in cases]:
                    raise ValueError("Swift Poly1305 differs from the independent polynomial oracle")
                provider = run([openssl, "version"]).decode().strip()
                for i, (key, message) in enumerate(direct, start=8):
                    observed = run([openssl, "mac", "-macopt", f"hexkey:{key.hex()}", "POLY1305"],
                                   input=message).decode().strip().lower()
                    if results[i] != observed:
                        raise ValueError("Swift Poly1305 differs from OpenSSL EVP-MAC")
                result = {"polynomial_cases": len(cases) - 8, "openssl_cases": len(direct),
                          "openssl_version": provider}
            else:
                if profile == "chacha20":
                    expected = [{"ciphertext": value} for value in results]
                else:
                    expected = [dict(zip(("ciphertext", "tag"), value.split("\t"))) for value in results]
                    cases = [{**case, **wire} for case, wire in zip(cases, expected)]
                response = oracle["node_cases"](cases)
                if response["output"] != expected:
                    raise ValueError(f"Swift {profile} differs from OpenSSL")
                result = {"openssl_cases": len(cases), "openssl_version": response["version"]}

            source = package / "Sources" / product / f"{name}.swift"
            report[profile] = {**result, "rfc_known": int(expected_kat), "api_boundary_checks": "passed",
                               "source_sha256": fingerprint(source),
                               "consumer_sha256": fingerprint(leaf / "tests/main.swift")}

        return {"status": "passed", "compiler": version, "results": report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=["chacha20", "poly1305", "aead", "all"])
    parser.add_argument("--swift", default="swift")
    parser.add_argument("--openssl", default=os.environ.get("ABC_OPENSSL") or shutil.which("openssl"))
    args = parser.parse_args()
    print(json.dumps(check(args.swift, args.openssl, args.profile), indent=2))


if __name__ == "__main__":
    main()
