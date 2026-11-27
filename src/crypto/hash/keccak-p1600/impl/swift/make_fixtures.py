"""Reproduce the Swift test fixtures from the shared FIPS 202 and OpenSSL oracles."""

import argparse
import base64
from itertools import islice
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
HASH_ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent / "cpp"))
from check import hash_cases, permutations


PROFILES = {
    "keccak-p1600": ("AbcKeccakP1600Swift", 17),
    "sha3-256": ("AbcSha3256Swift", 44),
    "shake256": ("AbcShake256Swift", 62),
}


def encode(raw):
    return base64.b64encode(raw).decode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=PROFILES)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    name, limit = PROFILES[args.profile]
    source = permutations() if args.profile == "keccak-p1600" else hash_cases(args.profile)
    entries = []
    known = splits = 0
    for role, message, expected, prefix in islice(source, limit):
        entries.append({"known": role == "known", "input": encode(message),
                        "expected": encode(expected), "prefix": encode(prefix)})
        known += role == "known"
        if args.profile != "keccak-p1600" and len(message) <= 273 and len(expected) <= 512:
            splits += len(message) + 1
    if len(entries) != limit:
        raise ValueError("Incomplete Swift conformance fixture selection")
    fixture = json.dumps(entries, indent=2) + "\n"
    output = HASH_ROOT / args.profile / f"impl/swift/{name}/Tests/{name}Tests/oracle.json"
    if args.check:
        if output.read_text(encoding="utf-8") != fixture:
            raise ValueError(f"Swift fixture mismatch: {output}")
    else:
        output.write_text(fixture, encoding="utf-8", newline="\n")
    print(f"known_answers={known}")
    print(f"oracle_comparisons={len(entries) - known}")
    print(f"streaming_splits={splits}")


if __name__ == "__main__":
    main()
