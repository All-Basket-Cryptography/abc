#!/usr/bin/env python3
"""Repository entry point for ABC's local assurance tooling."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

from tools.catalog.abc_status import build_docs, task_board


def doctor(repo):
    tools = {}
    for name in ("git", "cargo", "rustc", "lean", "lake", "charon", "aeneas", "node", "npm", "go", "javac", "clang"):
        binary = shutil.which(name)
        if binary is None:
            tools[name] = {"status": "missing"}
            continue
        try:
            argv = [binary, "version" if name == "go" else "--version"]
            process = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=10, cwd=repo, shell=False)
            version = (process.stdout or process.stderr).splitlines()
            tools[name] = {"status": "available" if process.returncode == 0 else "error", "path": binary,
                           "version": version[0] if version and process.returncode == 0 else None}
        except (OSError, subprocess.TimeoutExpired):
            tools[name] = {"status": "error", "path": binary}
    tools["python"] = {"status": "available", "path": sys.executable, "version": sys.version.split()[0]}
    return {"schema_version": 1, "tools": tools}


def output(value, destination=None):
    rendered = json.dumps(value, indent=2, ensure_ascii=True) + "\n"
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        print(rendered, end="")


def parser():
    root = argparse.ArgumentParser(prog="abc", description="ABC registry, impact planning, and assurance")
    commands = root.add_subparsers(dest="command", required=True)
    diagnostics = commands.add_parser("doctor", help="report actually available tools")
    diagnostics.add_argument("--json", action="store_true")
    registry = commands.add_parser("registry").add_subparsers(dest="action", required=True)
    registry.add_parser("validate").add_argument("--strict", action="store_true", help="strict validation is the default")
    graph = commands.add_parser("graph").add_subparsers(dest="action", required=True).add_parser("build")
    graph.add_argument("--revision", default="WORKTREE")
    graph.add_argument("--output", type=Path)
    plan = commands.add_parser("plan", help="select impacted verification tasks")
    plan.add_argument("--base")
    plan.add_argument("--head", default="WORKTREE")
    plan.add_argument("--merge-base", action="store_true")
    plan.add_argument("--output", type=Path)
    run = commands.add_parser("run", help="recompute a plan and execute its required tasks")
    run.add_argument("--plan", type=Path, required=True)
    run.add_argument("--output", type=Path, default=Path(".abc/run"))
    run.add_argument("--domain", choices=("local", "untrusted-pr"), default="local")
    run.add_argument("--key-file", type=Path, help="independently provisioned receipt key for local evidence")
    run.add_argument("--cache", type=Path, help="directory for authenticated log-only cache entries")
    evidence = commands.add_parser("evidence").add_subparsers(dest="action", required=True).add_parser("verify")
    evidence.add_argument("--plan", type=Path, required=True)
    evidence.add_argument("--run", type=Path, required=True)
    evidence.add_argument("--key-file", type=Path, required=True)
    evidence.add_argument("--domain", choices=("local", "untrusted-pr", "reviewed-main", "release"), default="local")
    commands.add_parser("status", help="validate and report the task board")
    package = commands.add_parser("package", help="build a local research SDK artifact")
    package.add_argument("--sdk", choices=("rust", "npm", "go", "java"), required=True)
    package.add_argument("--output", type=Path, default=Path("dist"))
    consumer = commands.add_parser("consumer-test", help="install and exercise an SDK artifact outside the workspace")
    consumer.add_argument("--sdk", choices=("rust", "npm", "go", "java"), required=True)
    consumer.add_argument("--artifact", type=Path, required=True)
    consumer.add_argument("--browser", type=Path, help="optional Chromium-family browser for the npm consumer")
    consumer.add_argument("--node-benchmark", action="store_true", help="measure the installed npm WASM provider and Node OpenSSL")
    conformance = commands.add_parser("conformance", help="package and test all seven Windows research SDKs")
    conformance.add_argument("--output", type=Path, required=True)
    conformance.add_argument("--browser", type=Path)
    fuzz = commands.add_parser("fuzz", help="run stateful SHA-256 differential fuzzing")
    fuzz.add_argument("--implementation", choices=("sha256-abc-rust-portable",), required=True)
    fuzz.add_argument("--budget", default="5s", help="an integer number of seconds from 1s to 600s")
    fuzz.add_argument("--coverage", action="store_true", help="collect LLVM source coverage on Windows")
    docs = commands.add_parser("docs").add_subparsers(dest="action", required=True).add_parser("build")
    docs.add_argument("--output", type=Path, default=Path(".abc/explorer"))
    release = commands.add_parser("release", help="prepare or replay a local research release set").add_subparsers(dest="action", required=True)
    prepare = release.add_parser("prepare")
    prepare.add_argument("--profile", choices=("research", "production"), required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--sdk", action="append", choices=("rust", "npm"))
    release.add_parser("verify").add_argument("--manifest", type=Path, required=True)
    return root


def main():
    args = parser().parse_args()
    repo = Path(__file__).resolve().parents[1]
    try:
        if args.command == "doctor":
            output(doctor(repo))
        elif args.command == "registry":
            from tools.catalog.abc_registry import validate
            summary = validate(repo)
            output({key: item for key, item in summary.items() if key != "records"})
        elif args.command == "graph":
            from tools.verification.abc_graph import build_graph
            output(build_graph(repo, args.revision), args.output)
        elif args.command == "plan":
            from tools.verification.abc_graph import create_plan
            output(create_plan(repo, args.base, args.head, merge_base=args.merge_base), args.output)
        elif args.command == "run":
            from tools.verification.abc_runner import execute
            result = execute(repo, args.plan, args.output, args.domain, args.key_file, args.cache)
            output(result)
            return 0 if result["status"] == "passed" else 1
        elif args.command == "evidence":
            from tools.verification.abc_runner import verify_receipt
            output(verify_receipt(repo, args.plan, args.run, args.domain, args.key_file))
        elif args.command == "status":
            output(task_board(repo))
        elif args.command == "package":
            if args.sdk == "go":
                from tools.release.abc_go import package_go
                output(package_go(repo, args.output))
            elif args.sdk == "java":
                from tools.release.abc_java import package_java
                output(package_java(repo, args.output))
            else:
                from tools.release.abc_package import package
                output(package(repo, args.sdk, args.output))
        elif args.command == "consumer-test":
            if args.sdk == "go":
                from tools.release.abc_go import check_go
                output(check_go(repo, args.artifact))
            elif args.sdk == "java":
                from tools.release.abc_java import check_java
                output(check_java(repo, args.artifact))
            else:
                from tools.release.abc_package import consumer_test
                output(consumer_test(repo, args.sdk, args.artifact, args.browser, args.node_benchmark))
        elif args.command == "conformance":
            from tools.release.abc_conformance import check_all
            output(check_all(repo, args.output, args.browser))
        elif args.command == "fuzz":
            if not args.budget.endswith("s") or not args.budget[:-1].isascii() or not args.budget[:-1].isdecimal():
                raise ValueError("fuzz budget must be an integer with an 's' suffix")
            seconds = int(args.budget[:-1])
            if not 1 <= seconds <= 600:
                raise ValueError("fuzz budget must be between 1s and 600s")
            engine = ["node", "src/crypto/hash/sha256/impl/rust/fuzz/run.mjs"]
            if sys.platform == "win32":
                engine.append("--source-coverage" if args.coverage else "--native")
            result = subprocess.run([*engine, str(seconds)], cwd=repo, timeout=seconds + 400, check=False)
            return result.returncode
        elif args.command == "docs":
            output(build_docs(repo, args.output))
        elif args.command == "release":
            from tools.release.abc_release import prepare, verify
            output(prepare(repo, args.output, args.profile, args.sdk or ["rust", "npm"])
                   if args.action == "prepare" else verify(repo, args.manifest))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "error", "message": str(error)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
