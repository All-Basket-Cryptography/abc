"""Plan and gate GitHub PR checks using tools from an approved base checkout."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from tools.abc_graph import create_plan
from tools.abc_runner import execute, _artifacts, _digest, _subset
from tools.abc_status import read_json


REQUIRED_METADATA = {"repository-assurance:registry", "repository-assurance:status"}
SHA = re.compile(r"[a-f0-9]{40}\Z")
BASELINE_ENTRY = "tools/abc_ci.py"
BOOTSTRAP_CHECKS = (
    ("-m", "tools.abc_cli", "registry", "validate", "--strict"),
    ("-m", "unittest", "discover", "-s", "fixtures/registry", "-p", "test_*.py"),
    ("-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"),
)


def _event_revisions(repo, base, head):
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        raise ValueError("The CI event must provide fixed base and head commit IDs")
    for revision in (base, head):
        kind = subprocess.check_output(["git", "cat-file", "-t", revision], cwd=repo)
        if kind.strip() != b"commit":
            raise ValueError(f"The CI revision is not a commit: {revision}")


def _has_baseline(repo, base):
    result = subprocess.run(["git", "cat-file", "-t", f"{base}:{BASELINE_ENTRY}"], cwd=repo, capture_output=True)
    return result.returncode == 0 and result.stdout.strip() == b"blob"


def _bootstrap(repo, base, head):
    _event_revisions(repo, base, head)
    if _has_baseline(repo, base):
        raise ValueError("A reviewed CI baseline exists; run the baseline workflow")
    ancestry = subprocess.run(["git", "merge-base", "--is-ancestor", base, head], cwd=repo, check=False)
    if ancestry.returncode or base == head:
        raise ValueError("Bootstrap requires the initial base commit to precede the candidate")
    checkout = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    if checkout != head or subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo):
        raise ValueError("Bootstrap fixtures require a clean checkout at the candidate commit")
    for check in BOOTSTRAP_CHECKS:
        subprocess.run([sys.executable, "-B", *check], cwd=repo, check=True, timeout=180)
    return {"status": "advisory-passed", "domain": "untrusted-pr", "head_revision": head,
            "review": "independent-review-required"}


def _plan(repo, base, head):
    _event_revisions(repo, base, head)
    if not _has_baseline(repo, base):
        raise ValueError("The reviewed CI baseline is absent; independent initial review is required")
    plan = create_plan(repo, base, head, merge_base=True)
    if plan["base_revision"] is None or plan["head_revision"] != head or plan["required_gate"] != "abc-required":
        raise ValueError("CI requires a real merge base and the fixed required gate")
    if not REQUIRED_METADATA <= set(plan["selected_tasks"]):
        raise ValueError("The required metadata tasks are missing from the plan")
    changes = subprocess.check_output(["git", "diff", "--name-only", "-z", "--no-renames", plan["base_revision"], head], cwd=repo)
    guarded = (".github/", "security/", "assurance/", "tools/abc_", "schemas/")
    changed = [name for name in changes.decode().split("\0") if name]
    protected = sorted(name for name in changed if name == "abc.py" or name.startswith(guarded) or name.endswith("module.toml"))
    if protected:
        raise ValueError(f"Independent review required for assurance changes: {', '.join(protected)}")
    if len(plan["selected_tasks"]) > 256:
        raise ValueError("Task matrix exceeds the hosted job limit")
    return plan


def gate(plan, downloaded):
    expected = {_digest(target): target for target in plan["selected_tasks"]}
    actual = {path.name: path for path in downloaded.iterdir()}
    if set(actual) != {f"abc-task-{key}" for key in expected} or not expected:
        raise ValueError("Incomplete or unexpected set of CI task artifacts")
    for key, target in expected.items():
        directory = actual[f"abc-task-{key}"]
        raw = read_json(directory / "receipt.json")
        receipt = raw["payload"]
        required = set(_subset(plan, target))
        if (raw["mac"] is not None or receipt["version"] != 1 or receipt["domain"] != "untrusted-pr"
                or receipt["target"] != target or receipt["head_revision"] != plan["head_revision"]
                or receipt["plan_digest"] != _digest(plan) or receipt["status"] != "passed"
                or receipt["inputs_unchanged"] is not True or set(receipt["results"]) != required):
            raise ValueError(f"Invalid CI receipt for {target}")
        for task, result in receipt["results"].items():
            needed = _artifacts(directory / "tasks" / _digest(task), plan["tasks"][task]["outputs"])
            if (result["status"] != "passed" or result["exit_code"] != 0 or result["cached"] is not False
                    or result["domain"] != "untrusted-pr" or result["artifacts"] != needed
                    or not re.fullmatch(r"[a-f0-9]{64}", result["fingerprint"])):
                raise ValueError(f"Missing or unsuccessful CI task {task}")
    return {"status": "passed", "domain": "untrusted-pr", "matrix_jobs": len(expected)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("bootstrap", "plan", "worker", "gate"))
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--target")
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    try:
        repo = args.repo.resolve()
        if args.mode == "bootstrap":
            print(json.dumps(_bootstrap(repo, args.base, args.head)))
            return 0
        plan = _plan(repo, args.base, args.head)
        if args.mode == "plan":
            matrix = {"include": [{"target": name, "artifact": _digest(name)} for name in plan["selected_tasks"]]}
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                print(f"matrix={json.dumps(matrix, separators=(',', ':'))}", file=stream)
            return 0
        if args.mode == "gate":
            print(json.dumps(gate(plan, args.directory)))
            return 0
        args.directory.parent.mkdir(parents=True, exist_ok=True)
        plan_path = args.directory.parent / "plan.json"
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        receipt = execute(repo, plan_path, args.directory, "untrusted-pr", target=args.target)
        print(json.dumps({"target": args.target, "status": receipt["status"], "tasks": {name: item["status"] for name, item in receipt["results"].items()}}))
        return 0 if receipt["status"] == "passed" else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"ABC CI: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
