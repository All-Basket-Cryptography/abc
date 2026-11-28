"""Inventory and replay the repository's 20-profile native SDK test matrix."""

import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import cache
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
from shutil import which
from subprocess import DEVNULL, STDOUT, TimeoutExpired, check_output, run

from tools.verification.abc_graph import build_graph


ROOT = Path(__file__).resolve().parents[3]
PROFILES = (
    "hash/sha256", "hash/sha512", "hash/sha3-256", "hash/shake256", "hash/blake2b",
    "mac/hmac-sha256", "kdf/hkdf-sha256", "kdf/pbkdf2-hmac-sha256", "kdf/scrypt", "kdf/argon2id",
    "cipher/aes256", "aead/aes256-gcm", "cipher/chacha20", "mac/poly1305", "aead/chacha20-poly1305",
    "agreement/x25519", "signature/ed25519", "signature/ecdsa-p256-sha256",
    "agreement/ml-kem-768", "signature/ml-dsa-65",
)
LANGUAGES = ("c", "cpp", "csharp", "go", "java", "javascript", "kotlin", "python", "rust", "swift", "typescript")


@dataclass(frozen=True)
class Check:
    name: str
    command: list[str]
    timeout: int
    inputs: tuple[str, ...]


def json_digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_report(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def describe(graph):
    tests = defaultdict(list)
    for name in graph["topological_order"]:
        task = graph["tasks"][name]
        if task["kind"] == "test":
            tests[task["module"]].append((name, task))
    modules = {value["manifest"]: module for module, value in graph["modules"].items()}
    requires = defaultdict(set)
    for edge in graph["module_edges"]:
        requires[edge["consumer"]].add(edge["prerequisite"])

    def closure(start):
        seen, frontier = set(), [start]
        while frontier:
            module = frontier.pop()
            if module not in seen:
                seen.add(module)
                frontier.extend(requires[module])
        return {path for name in seen for path in graph["modules"][name]["inputs"]}

    for language in LANGUAGES:
        for profile in PROFILES:
            leaf = f"src/crypto/{profile}/impl/{language}"
            if language == "rust":
                manifest = f"{leaf}/Cargo.toml"
                owner = graph["owners"][manifest]
                paths = closure(owner)
                release = ["cargo", "+1.92.0", "test", "--locked", "--offline", "--release", "--manifest-path", manifest]
                checks = [Check(f"{owner}:portfolio-release", release, 300, tuple(sorted(paths)))]
            else:
                owner = modules[f"{leaf}/module.toml"]
                checks = [Check(name, task["command"], task["timeout_seconds"], tuple(task["inputs"]))
                          for name, task in tests[owner]]
                if not checks:
                    raise ValueError(f"No primary test task for {leaf}")
            yield language, profile, checks


def fingerprints(cells):
    @cache
    def digest(path):
        return sha256((ROOT / path).read_bytes()).hexdigest()

    # Track source and build inputs used by these native tests. Global release policy and
    # the separate formal proof inputs have their own verifier in tools/verification.
    fingerprints_by_cell = {}
    for language, profile, checks in cells:
        files = {path: digest(path) for check in checks for path in check.inputs
                 if path.startswith(("src/crypto/", "tools/build/")) and not path.endswith((".md", ".lean"))}
        tasks = {check.name: {"command": check.command, "timeout_seconds": check.timeout} for check in checks}
        fingerprints_by_cell[language, profile] = json_digest({"files": files, "tasks": tasks})
    return fingerprints_by_cell


def log_name(language, profile, number):
    return f"{language}-{profile.split('/')[-1]}-{number}.log"


def run_cell(language, profile, checks, output):
    env = dict(os.environ)
    if (language == "rust" and profile in ("agreement/ml-kem-768", "signature/ml-dsa-65")
            and "ABC_PORTFOLIO_PQ_CARGO_HOME" in env):
        env["CARGO_HOME"] = env["ABC_PORTFOLIO_PQ_CARGO_HOME"]
    if language == "go" and profile == "signature/ecdsa-p256-sha256" and "ABC_PORTFOLIO_ECDSA_GO_TOOLCHAIN" in env:
        env["GOTOOLCHAIN"] = env["ABC_PORTFOLIO_ECDSA_GO_TOOLCHAIN"]

    results = []
    for number, check in enumerate(checks, start=1):
        name = log_name(language, profile, number)
        log = output / name
        executable = which(check.command[0], path=env.get("PATH"))
        code = None
        with log.open("wb") as capture:
            if executable is None:
                status = "not_run"
                capture.write(f"Missing tool {check.command[0]}\n".encode())
            else:
                try:
                    code = run([executable, *check.command[1:]], cwd=ROOT, env=env, stdout=capture,
                               stderr=STDOUT, stdin=DEVNULL, timeout=check.timeout, check=False).returncode
                    status = "passed" if code == 0 else "failed"
                except TimeoutExpired:
                    status = "timeout"
                except OSError as error:
                    status = "failed"
                    capture.write(f"{type(error).__name__}: {error}\n".encode())
        results.append({"task": check.name, "command": check.command, "exit_code": code, "status": status,
                        "log": name, "log_sha256": sha256(log.read_bytes()).hexdigest()})
    return results


def verify(receipt_dir, cells):
    receipt = json.loads((receipt_dir / "result.json").read_text(encoding="utf-8"))
    if receipt["status"] != "passed" or receipt["inputs_unchanged"] is not True:
        raise ValueError("The receipt does not report a successful replay with unchanged inputs")
    results = receipt["results"]
    by_cell = {(row["language"], row["profile"]): row for row in results}
    chosen = {language for language, _ in by_cell}
    selected = [cell for cell in cells if cell[0] in chosen]
    expected = {(language, profile) for language, profile, _ in selected}
    if not results or len(results) != len(by_cell) or set(by_cell) != expected:
        raise ValueError("The receipt must contain each profile exactly once for each claimed language")
    if len(results) != receipt["cells"] or len(results) != receipt["passed_cells"]:
        raise ValueError("The receipt totals differ from the selected matrix")

    current = fingerprints(selected)
    for language, profile, checks in selected:
        row = by_cell[language, profile]
        if row["passed"] is not True or row["inputs_sha256"] != current[language, profile]:
            raise ValueError(f"Result or source inputs changed for {language}/{profile}")
        if len(row["checks"]) != len(checks):
            raise ValueError(f"Missing test command results for {language}/{profile}")
        for number, (observed, check) in enumerate(zip(row["checks"], checks), start=1):
            name = log_name(language, profile, number)
            if (observed["task"] != check.name or observed["command"] != check.command
                    or observed["status"] != "passed" or type(observed["exit_code"]) is not int
                    or observed["exit_code"] != 0 or observed["log"] != name):
                raise ValueError(f"Result fields differ for {check.name}")
            log = receipt_dir / name
            if log.is_symlink() or sha256(log.read_bytes()).hexdigest() != observed["log_sha256"]:
                raise ValueError(f"Log changed for {check.name}")
    return len(results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--inventory", action="store_true", help="list every profile/language without executing tools")
    mode.add_argument("--verify", type=Path, help="check an advisory receipt's commands, inputs and log digests")
    parser.add_argument("--languages", nargs="+", choices=LANGUAGES,
                        default=LANGUAGES if platform.system() == "Darwin" else tuple(x for x in LANGUAGES if x != "swift"))
    parser.add_argument("--workers", type=int, default=1, help="run this many language lanes concurrently")
    parser.add_argument("--output", type=Path, help="new directory for execution results and per-task logs")
    args = parser.parse_args()
    cells = list(describe(build_graph(ROOT)))
    if args.inventory:
        print(json.dumps([{"language": language, "profile": profile, "checks": [check.name for check in checks]}
                          for language, profile, checks in cells], indent=2))
        return 0
    if args.verify:
        try:
            count = verify(args.verify, cells)
        except (OSError, KeyError, TypeError, ValueError) as error:
            parser.exit(1, f"Receipt verification failed: {error}\n")
        print(f"Verified {count} advisory matrix cells against current source and saved logs.")
        return 0
    if not args.output or args.workers < 1:
        parser.error("execution requires --output and a positive --workers value")

    selected = [cell for cell in cells if cell[0] in args.languages]
    sources = fingerprints(selected)
    revision = check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)

    def lane(language):
        results = []
        for type_name, profile, checks in selected:
            if type_name != language:
                continue
            cases = run_cell(language, profile, checks, output)
            results.append({"language": language, "profile": profile, "inputs_sha256": sources[language, profile],
                            "checks": cases, "passed": all(case["status"] == "passed" for case in cases)})
        write_report(output / f"{language}.json", results)
        print(f"{language}: {sum(result['passed'] for result in results)}/{len(results)} passed", flush=True)
        return results

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = [result for group in pool.map(lane, sorted(set(args.languages))) for result in group]
    current = [cell for cell in describe(build_graph(ROOT)) if cell[0] in args.languages]
    unchanged = fingerprints(current) == sources
    passed_cells = sum(result["passed"] for result in results)
    passed = unchanged and passed_cells == len(selected)
    write_report(output / "result.json", {"revision": revision, "platform": platform.platform(),
                 "status": "passed" if passed else "failed", "inputs_unchanged": unchanged,
                 "cells": len(selected), "passed_cells": passed_cells, "results": results})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
