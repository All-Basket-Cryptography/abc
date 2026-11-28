"""Run the independent SHA-256 SwiftPM suite with Apple Swift 6.1.2 on macOS."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "Sources/AbcSha256Swift/Sha256.swift"
TEST = HERE / "Tests/AbcSha256SwiftTests/Sha256Tests.swift"


def fingerprint(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check(output):
    compiler = subprocess.check_output(["swift", "--version"], stderr=subprocess.STDOUT,
                                       text=True, timeout=15).strip()
    if (not re.search(r"\bApple Swift version 6\.1\.2(?=\s|$)", compiler)
            or not re.search(r"^Target: \S+-apple-macosx\S*$", compiler, re.MULTILINE)):
        raise ValueError(f"Expected Apple Swift 6.1.2 on macOS, found {compiler}")

    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="abc-sha256-swift-build-") as build:
        command = ["swift", "test", "--package-path", str(HERE), "--scratch-path", build,
                   "--configuration", "release", "-Xswiftc", "-warnings-as-errors"]
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=180)
    log = result.stdout
    (output / "swift-test.log").write_text(log, encoding="utf-8")
    print(log, end="")
    result.check_returncode()
    counts = {name: int(value) for name, value in re.findall(
        r"^(known_answers|one_shot_comparisons|streaming_snapshots)=(\d+)$", log, re.MULTILINE
    )}
    if (counts.get("known_answers") != 3 or counts.get("one_shot_comparisons") != 154
            or counts.get("streaming_snapshots", 0) < 154
            or not re.search(r"Executed 2 tests?, with 0 failures", log)):
        raise ValueError("SwiftPM did not report the expected completed test suite")

    report = {
        "status": "passed",
        "toolchain": compiler,
        "configuration": "release",
        "target_os": subprocess.check_output(["sw_vers", "-productVersion"], text=True, timeout=15).strip(),
        "oracle": "Apple CryptoKit SHA256",
        "source_sha256": fingerprint(SOURCE),
        "test_sha256": fingerprint(TEST),
        "checks": counts | {"range_and_value_state": "passed"},
    }
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="retain the logs and check report")
    options = parser.parse_args()
    if options.output:
        report = check(options.output.resolve())
    else:
        with TemporaryDirectory(prefix="abc-sha256-swift-check-") as output:
            report = check(Path(output))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
