"""Propose and resume independently reviewed local research runs."""

from argparse import ArgumentParser
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from uuid import uuid4

from tools.abc_graph import create_plan
from tools.abc_runner import (
    _authenticate, _digest, _file_digest, _fingerprints, _fresh_plan, _key, _sign,
    _subset, _within, _write_json, execute, verify_receipt,
)
from tools.abc_status import _unique_object, read_json

REPO = Path(__file__).resolve().parents[1]
NAMESPACE = "abc-local-research"
STATUS = {"reserved", "interrupted", "passed", "failed"}


def _scope(repo, directory):
    repo = repo.resolve()
    directory = directory.resolve()
    if directory.is_relative_to(repo):
        path = directory.relative_to(repo)
        ignored = subprocess.run(
            ["git", "check-ignore", "--quiet", "--", path.as_posix()],
            cwd=repo, capture_output=True, timeout=10,
        )
        if ignored.returncode != 0:
            raise ValueError("Use a Git-ignored checkpoint directory or a directory outside the checkout")
    return repo, directory


def _execution_scope(repo, plan, target, max_attempts, budget_seconds):
    if type(max_attempts) is not int or max_attempts < 1 or type(budget_seconds) is not int:
        raise ValueError("The proposal requires a positive attempt limit and execution budget")
    selected = _subset(plan, target)
    if not selected:
        raise ValueError("The selected research scope has no runnable tasks")
    allowance = sum(plan["tasks"][name]["timeout_seconds"] for name in selected)
    if budget_seconds < allowance * max_attempts:
        raise ValueError(f"Execution budget requires at least {allowance * max_attempts} task-seconds")
    fingerprints, _, _ = _fingerprints(repo, plan, "local", target)
    return selected, allowance, fingerprints


def propose(repo, directory, *, base=None, head="WORKTREE", merge_base=False, target=None,
            max_attempts=1, budget_seconds):
    """Create an unsigned proposal bound to a fresh plan and its local inputs."""
    repo, directory = _scope(repo, directory)
    plan = create_plan(repo, base, head, merge_base=merge_base)
    selected, allowance, fingerprints = _execution_scope(repo, plan, target, max_attempts, budget_seconds)
    proposal = {
        "schema_version": 1, "scope": NAMESPACE, "session": uuid4().hex,
        "repo": str(repo), "directory": str(directory), "target": target,
        "plan_digest": _digest(plan), "task_order": selected, "fingerprints": fingerprints,
        "controller": _file_digest(Path(__file__)), "max_attempts": max_attempts,
        "budget_seconds": budget_seconds, "task_seconds_per_attempt": allowance,
    }
    directory.mkdir(parents=True, exist_ok=False)
    _write_json(directory / "plan.json", plan)
    _write_json(directory / "proposal.json", proposal)
    return proposal


def _approval(repo, path, signature, signers, reviewer):
    authority = Path(signers).resolve(strict=True)
    if authority.is_relative_to(repo) or authority.is_relative_to(path.parent):
        raise ValueError("The reviewer allowlist must be outside checkout and checkpoint storage")
    tool = shutil.which("ssh-keygen")
    if tool is None or Path(tool).resolve().is_relative_to(repo):
        raise ValueError("External OpenSSH ssh-keygen is required for independent review")
    payload = path.read_bytes()
    command = [
        str(Path(tool).resolve()), "-Y", "verify", "-f", str(authority), "-I", reviewer,
        "-n", NAMESPACE, "-s", str(signature.resolve(strict=True)),
    ]
    result = subprocess.run(command, input=payload, capture_output=True, timeout=10, cwd=authority.parent)
    if result.returncode != 0:
        raise ValueError("Independent proposal signature verification failed")
    return json.loads(payload, object_pairs_hook=_unique_object)


@contextmanager
def _session_lock(directory):
    # The operating system releases either lock if its holder exits unexpectedly.
    with (directory / "resume.lock").open("a+b") as lock:
        lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise ValueError("This research checkpoint is already in use") from error
        yield


def _save(path, checkpoint, key):
    _write_json(path, _sign(checkpoint, key))


def _attempt_directory(directory, index):
    return _within(directory, f"attempt-{index:04d}")


def _close_attempt(repo, plan_path, plan, directory, proposal, attempt, key_file, key):
    location = _attempt_directory(directory, attempt["index"])
    path = location / "receipt.json"
    if not path.is_file():
        if attempt["status"] not in {"reserved", "interrupted"}:
            raise ValueError("A previously recorded attempt receipt is missing")
        attempt["status"] = "interrupted"
        return
    digest = _file_digest(path)
    if attempt["receipt"] not in (None, digest):
        raise ValueError("Attempt receipt digest differs from the checkpoint")
    receipt = _authenticate(read_json(path), key)
    results = receipt["results"]
    if (receipt["version"] != 1 or receipt["domain"] != "local"
            or receipt["plan_digest"] != proposal["plan_digest"] or receipt["target"] != proposal["target"]
            or receipt["head_revision"] != plan["head_revision"] or receipt["status"] not in {"passed", "failed"}
            or {name: value["fingerprint"] for name, value in results.items()} != proposal["fingerprints"]):
        raise ValueError("Attempt receipt does not match the approved plan")
    if receipt["status"] == "passed":
        verify_receipt(repo, plan_path, location, "local", key_file, target=proposal["target"])
    else:
        for name, result in results.items():
            task = location / "tasks" / _digest(name)
            for artifact, expected in result["artifacts"].items():
                if _file_digest(_within(task, artifact)) != expected:
                    raise ValueError(f"Recorded attempt artifact changed: {name}/{artifact}")
    attempt.update(
        status=receipt["status"], receipt=digest,
        task_statuses={name: result["status"] for name, result in results.items()},
        task_elapsed_ms=sum(result["elapsed_ms"] for result in results.values()),
        cached_tasks=[name for name, result in results.items() if result["cached"]],
    )


def _checkpoint(directory, proposal_digest, reviewer, key):
    path = directory / "checkpoint.json"
    attempts_on_disk = {path.name for path in directory.glob("attempt-*")}
    if path.exists():
        checkpoint = _authenticate(read_json(path), key)
        if checkpoint["proposal_digest"] != proposal_digest or checkpoint["reviewer"] != reviewer:
            raise ValueError("Checkpoint is bound to a different proposal or reviewer")
    else:
        checkpoint = {"proposal_digest": proposal_digest, "reviewer": reviewer, "attempts": []}
    for index, attempt in enumerate(checkpoint["attempts"], start=1):
        if attempt["index"] != index or attempt["status"] not in STATUS:
            raise ValueError("Invalid sequential checkpoint attempt")
        attempts_on_disk.discard(f"attempt-{index:04d}")
    if attempts_on_disk:
        raise ValueError("Attempt directories exist without authenticated checkpoint entries")
    return path, checkpoint


def resume(repo, directory, *, signature, signers, reviewer, key_file):
    """Verify approval and execute or recover one bounded local attempt."""
    repo, directory = _scope(repo, directory)
    key_file = key_file.resolve(strict=True)
    if key_file.is_relative_to(repo) or key_file.is_relative_to(directory):
        raise ValueError("The independent receipt key must be outside checkout and checkpoint storage")
    key = _key(key_file)
    with _session_lock(directory):
        proposal = _approval(repo, directory / "proposal.json", signature, signers, reviewer)
        if (proposal["schema_version"] != 1 or proposal["repo"] != str(repo)
                or proposal["directory"] != str(directory) or proposal["scope"] != NAMESPACE
                or proposal["controller"] != _file_digest(Path(__file__))):
            raise ValueError("Proposal does not match the checkout, session directory or research controller")
        plan_path = directory / "plan.json"
        plan = _fresh_plan(repo, plan_path)
        if _digest(plan) != proposal["plan_digest"]:
            raise ValueError("Fresh plan digest differs from the approved proposal")
        selected, allowance, fingerprints = _execution_scope(
            repo, plan, proposal["target"], proposal["max_attempts"], proposal["budget_seconds"],
        )
        if (selected != proposal["task_order"] or allowance != proposal["task_seconds_per_attempt"]
                or fingerprints != proposal["fingerprints"]):
            raise ValueError("Fresh task scope, budget or input fingerprints differ from the approved proposal")
        checkpoint_path, checkpoint = _checkpoint(directory, _digest(proposal), reviewer, key)
        attempts = checkpoint["attempts"]
        for attempt in attempts:
            _close_attempt(repo, plan_path, plan, directory, proposal, attempt, key_file, key)
        if attempts:
            _save(checkpoint_path, checkpoint, key)
        if attempts and attempts[-1]["status"] == "passed":
            return {"status": "passed", "scope": NAMESPACE, **checkpoint}
        if len(attempts) >= proposal["max_attempts"]:
            return {"status": "budget_exhausted", "scope": NAMESPACE, **checkpoint}
        attempt = {"index": len(attempts) + 1, "status": "reserved", "receipt": None}
        attempts.append(attempt)
        _save(checkpoint_path, checkpoint, key)
        execute(repo, plan_path, _attempt_directory(directory, attempt["index"]), "local",
                key_file, directory / "cache", target=proposal["target"])
        _close_attempt(repo, plan_path, plan, directory, proposal, attempt, key_file, key)
        _save(checkpoint_path, checkpoint, key)
        return {"status": attempt["status"], "scope": NAMESPACE, **checkpoint}


def main():
    parser = ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    proposal = commands.add_parser("propose")
    proposal.add_argument("--directory", type=Path, required=True)
    proposal.add_argument("--base")
    proposal.add_argument("--head", default="WORKTREE")
    proposal.add_argument("--merge-base", action="store_true")
    proposal.add_argument("--target")
    proposal.add_argument("--max-attempts", type=int, default=1)
    proposal.add_argument("--budget-seconds", type=int, required=True)
    restart = commands.add_parser("resume")
    restart.add_argument("--directory", type=Path, required=True)
    restart.add_argument("--signature", type=Path, required=True)
    restart.add_argument("--allowed-signers", dest="signers", type=Path, required=True)
    restart.add_argument("--reviewer", required=True)
    restart.add_argument("--receipt-key", dest="key_file", type=Path, required=True)
    arguments = vars(parser.parse_args())
    command = arguments.pop("command")
    try:
        result = (propose if command == "propose" else resume)(REPO, **arguments)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return int(command == "resume" and result["status"] != "passed")


if __name__ == "__main__":
    sys.exit(main())
