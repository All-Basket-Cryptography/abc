"""Build provider-backed SwiftPM consumers and compare against RFC, ACVP and Go."""

import argparse
import json
from pathlib import Path
import random
import runpy
import shutil
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
CRYPTO = HERE.parents[3]
CURVE_HARNESS = CRYPTO / "agreement/x25519/impl/swift/check.py"
GO_ORACLE = CRYPTO / "agreement/ml-kem-768/impl/swift/tests/oracle.go"
PROFILES = {
    "argon2id": ("kdf/argon2id", "Argon2id", {"cases": "110", "bounds": "passed"}),
    "ecdsa-p256-sha256": ("signature/ecdsa-p256-sha256", "EcdsaP256",
                         {"rfc_known": "3", "candidate_retries": "2", "provider_retries": "2",
                          "interoperability": "48", "bounds": "passed"}),
    "ml-kem-768": ("agreement/ml-kem-768", "MlKem768", {"acvp_known": "2", "go_cases": "12", "bounds": "passed"}),
    "ml-dsa-65": ("signature/ml-dsa-65", "MlDsa65", {"acvp_known": "4", "go_cases": "12", "bounds": "passed"}),
}


def run(*command, input=None):
    result = subprocess.run(command, input=input, capture_output=True, text=True, encoding="utf-8", timeout=200)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def argon_fixtures(rng):
    cases = []

    def add(memory, passes, lanes, tag):
        i = len(cases)
        widths = ((0, 1, 31, 32, 129)[i % 5], (8, 16, 32)[i % 3], (0, 1, 8, 65)[i % 4],
                  (0, 1, 12, 129)[i % 4])
        payload = [rng.randbytes(n).hex() for n in widths]
        cases.append(":".join(map(str, [memory, passes, lanes, tag, *payload])))

    for lanes in (1, 2, 3, 4):
        for segment in (2, 3, 4, 7, 11):
            for tag in (4, 16, 32, 64, 65):
                index = len(cases)
                add(4 * lanes * segment + index % (4 * lanes), 1 + index % 4, lanes, tag)
    for index, tag in enumerate((33, 63, 64, 65, 96, 97, 128, 129, 257)):
        lanes = 1 + index % 3
        add(4 * lanes * (127 + index // 3), 1 + index % 3, lanes, tag)
    cases.append(":".join(["32", "3", "4", "32", "01" * 32, "02" * 16, "03" * 8, "04" * 12]))
    go = CRYPTO / "kdf/argon2id/impl/go"
    result = run("go", "run", "-C", str(go), "./internal/differential", input="\n".join(cases) + "\n").splitlines()
    if len(result) != len(cases) or result[-1] != "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659":
        raise ValueError("Go Argon2id reference did not match RFC 9106")
    return [f"{case}:{output}" for case, output in zip(cases, result, strict=True)]


def pq_reference(profile, rows):
    return run("go", "run", str(GO_ORACLE), profile, input="\n".join(rows) + "\n").splitlines()


def fixtures(profile):
    rng = random.Random(2032046979)
    if profile == "argon2id":
        return argon_fixtures(rng)
    if profile == "ecdsa-p256-sha256":
        return []
    if profile == "ml-kem-768":
        corpus = json.loads((CRYPTO / "agreement/ml-kem-768/spec/acvp.json").read_text(encoding="utf-8"))
        known = [f"{x['d']}{x['z']}:{x['ek']}" for x in corpus["cases"] if "d" in x]
        seeds = [row.split(":")[0] for row in known] + [rng.randbytes(64).hex() for _ in range(10)]
        return known + pq_reference("kem", seeds)
    corpus = json.loads((CRYPTO / "signature/ml-dsa-65/spec/acvp-fips204-sample.json").read_text(encoding="utf-8"))
    seed = corpus["keyGen"]["seed"]
    known = [f"{seed}:{corpus['keyGen']['public_key_sha256']}"]
    for item in [*corpus["sigGen"]["cases"], *corpus["sigVer"]["cases"]]:
        should_verify = "01" if item.get("testPassed", True) else "00"
        known.append(":".join([should_verify, item["pk"], item["message"], item["context"], item["signature"]]))
    inputs = [":".join([seed if i == 0 else rng.randbytes(32).hex(), rng.randbytes(i * 29).hex(),
                        rng.randbytes([0, 1, 7, 255][i % 4]).hex()]) for i in range(12)]
    return known + pq_reference("dsa", inputs)


def check(profile, swift):
    version = run(swift, "--version").strip()
    if "Apple Swift version 6.1.2 " not in version or "Target: arm64-apple-macosx" not in version:
        raise ValueError(f"Expected Apple Swift 6.1.2 for macOS arm64, got {version}")
    libcrypto = run("pkg-config", "--modversion", "libcrypto").strip()
    if libcrypto != "3.5.9":
        raise ValueError(f"Expected OpenSSL qualification version 3.5.9, got {libcrypto}")
    reference_version = run("go", "version").strip() if profile != "ecdsa-p256-sha256" else None
    common = runpy.run_path(str(CURVE_HARNESS))
    path, name, expected = PROFILES[profile]
    leaf = CRYPTO / path / "impl/swift"
    target = f"Abc{name}Swift"
    package = leaf / target
    test = leaf / "tests/main.swift"
    with TemporaryDirectory(prefix="abc-swift-provider-consumer-") as directory:
        work = Path(directory)
        consumer = work / "consumer"
        sources = consumer / "Sources/Consumer"
        sources.mkdir(parents=True)
        shutil.copy2(test, sources)
        shutil.copy2(CURVE_HARNESS.parent / "tests/Support.swift", sources)
        (consumer / "Package.swift").write_text(common["consumer_manifest"](package, target), encoding="utf-8")
        fixture = work / "fixtures.txt"
        fixture.write_text("\n".join(fixtures(profile)) + "\n", encoding="utf-8")

        args = [swift, "run", "--package-path", str(consumer), "--scratch-path", str(work / "build"),
                "--configuration", "release", "-Xswiftc", "-warnings-as-errors"]
        if profile == "ecdsa-p256-sha256":
            args.extend(["-Xswiftc", "-enable-testing"])
        args.extend(["Consumer", str(fixture)])
        observed, reciprocal = {}, []
        for line in run(*args).splitlines():
            key, value = line.split("=", 1)
            if key == "reciprocal":
                reciprocal.append(value.split(":"))
            else:
                observed[key] = value
        if observed != expected:
            raise ValueError(f"Incomplete Swift {profile} conformance evidence: {observed}")
        if profile == "ml-kem-768":
            if len(reciprocal) != 12 or pq_reference("decap", [f"{seed}:{ct}" for seed, ct, _ in reciprocal]) != [
                shared for _, _, shared in reciprocal
            ]:
                raise ValueError("Go could not decapsulate the Swift ciphertexts")

        source = next((package / "Sources" / target).glob("*.swift"))
        shim = package / "Sources" / f"CAbc{name}OpenSSL/shim.h"
        fingerprint = common["fingerprint"]
        return {"status": "passed", "profile": profile, "toolchain": version, "openssl": libcrypto,
                "go_oracle": reference_version, "checks": observed,
                "source_sha256": fingerprint(source), "binding_sha256": fingerprint(shim),
                "consumer_sha256": fingerprint(test), "fixture_sha256": fingerprint(fixture)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=list(PROFILES))
    parser.add_argument("--swift", default="swift")
    args = parser.parse_args()
    print(json.dumps(check(args.profile, args.swift), indent=2))


if __name__ == "__main__":
    main()
