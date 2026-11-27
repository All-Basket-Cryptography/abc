"""Execute fresh plans and authenticate local receipts with an independent key."""

from hashlib import sha256
from hmac import compare_digest, digest as mac
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import signal
import subprocess
import sys
import time
from uuid import uuid4

from tools.verification.abc_graph import create_plan
from tools.catalog.abc_status import read_json


DOMAINS = {"local", "untrusted-pr"}
PROGRAMS = {"python", "cargo", "rustc", "rustup", "git", "node", "npm", "go", "javac", "java", "clang", "lean", "lake", "charon", "aeneas", "bash"}
ENVIRONMENT_KEYS = {
    "PATH", "SYSTEMROOT", "WINDIR", "USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH", "TEMP", "TMP", "TMPDIR",
    "PATHEXT", "APPDATA", "LOCALAPPDATA", "COMSPEC", "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMDATA",
    "JAVA_HOME", "ABC_JAVA_HOME", "ABC_DOTNET", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN",
    "LIB", "LIBPATH", "INCLUDE", "VCTOOLSINSTALLDIR", "WINDOWSSDKDIR", "WINDOWSSDKVERSION",
    "UCRTVERSION", "UNIVERSALCRTSDKDIR", "VSCMD_ARG_TGT_ARCH", "VSCMD_ARG_HOST_ARCH",
}
VERIFIER_INPUTS = ("tools/abc_cli.py", "tools/verification/abc_graph.py", "tools/verification/abc_runner.py", "registry/policy/assurance-policy.json")


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value):
    return sha256(_encoded(value)).hexdigest()


def _write_json(path, value):
    tmp = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    with tmp.open("xb") as file:
        file.write(_encoded(value) + b"\n")
    tmp.replace(path)


def _within(root, name):
    path = PurePosixPath(name)
    if path.as_posix() != name or path.is_absolute() or name in {"", "."} or ".." in path.parts or ":" in name or "\\" in name:
        raise ValueError(f"Unsafe task path {name!r}")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError(f"Task path escapes its root: {name}")
    return resolved


def _file_digest(path):
    with path.open("rb") as file:
        from hashlib import file_digest
        return {"sha256": file_digest(file, "sha256").hexdigest(), "size_bytes": file.tell()}


def _subset(plan, target):
    if target is None:
        return plan["selected_tasks"]
    if target not in plan["tasks"]:
        raise ValueError(f"Task is not selected: {target}")
    required = {target}
    for name in reversed(plan["selected_tasks"]):
        if name in required:
            required.update(plan["tasks"][name]["dependencies"])
    return [name for name in plan["selected_tasks"] if name in required]


def _environment():
    env = {key: value for key, value in os.environ.items() if key.upper() in ENVIRONMENT_KEYS}
    env.update({"TZ": "UTC", "LC_ALL": "C", "PYTHONUTF8": "1", "CARGO_NET_OFFLINE": "true"})
    return env


def _tool(name, repo, env):
    if name not in PROGRAMS:
        raise ValueError(f"Unsupported task executable {name!r}")
    binary = sys.executable if name == "python" else shutil.which(name)
    if not binary:
        return {"status": "missing"}
    path = Path(binary).resolve()
    if path.is_relative_to(repo.resolve()) or path.suffix.lower() in {".bat", ".cmd", ".ps1"}:
        raise ValueError(f"No supported external executable found for {name}")
    version_args = ["version"] if name == "go" else ["--version"]
    if name in {"cargo", "rustc"}:
        version_args = ["-Vv"]
    process = subprocess.run([str(path), *version_args], cwd=repo, env=env, capture_output=True, timeout=10)
    if process.returncode:
        raise ValueError(f"Could not identify {name}: exit {process.returncode}")
    identity = {"path": str(path), "binary": _file_digest(path), "version_output": sha256(process.stdout + process.stderr).hexdigest()}
    rustup = shutil.which("rustup") if name in {"cargo", "rustc"} else None
    if rustup:
        result = subprocess.run([rustup, "which", name], cwd=repo, env=env, capture_output=True, timeout=10, text=True)
        if result.returncode == 0:
            identity["toolchain_binary"] = _file_digest(Path(result.stdout.strip()))
    return identity


def _fresh_plan(repo, plan_path):
    candidate = read_json(plan_path)
    if not isinstance(candidate, dict) or not {"requested_base", "requested_head", "merge_base"} <= candidate.keys():
        raise ValueError("Invalid plan revision inputs")
    if ((candidate["requested_base"] is not None and not isinstance(candidate["requested_base"], str))
            or not isinstance(candidate["requested_head"], str) or type(candidate["merge_base"]) is not bool):
        raise ValueError("Invalid plan revision types")
    plan = create_plan(repo, candidate["requested_base"], candidate["requested_head"], merge_base=candidate["merge_base"])
    if candidate != plan:
        raise ValueError("Plan no longer matches the independently recomputed task selection")
    head = candidate["requested_head"]
    if head != "WORKTREE":
        resolved = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        changed = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo)
        if resolved != plan["head_revision"] or changed:
            raise ValueError("Execution requires a clean checkout at the plan head")
    return plan


def _fingerprints(repo, plan, domain, target=None):
    env = _environment()
    tool_ids = {}
    policy = {name: _file_digest(repo / name) for name in VERIFIER_INPUTS}
    environment = {"platform": platform.platform(), "machine": platform.machine(), "variables": env}
    fingerprints = {}
    for name in _subset(plan, target):
        task = plan["tasks"][name]
        tools = sorted(set([task["command"][0], *task.get("tools", [])]))
        for tool in tools:
            if tool not in tool_ids:
                tool_ids[tool] = _tool(tool, repo, env)
        inputs = {name: _file_digest(_within(repo, name)) for name in sorted(set(task["inputs"]))}
        upstream = {dependency: fingerprints[dependency] for dependency in task["dependencies"]}
        fingerprints[name] = _digest({"version": 1, "task": task, "files": inputs, "upstream": upstream,
                                      "host": environment, "domain": domain, "policy": policy,
                                      "tools": {tool: tool_ids[tool] for tool in tools}})
    return fingerprints, tool_ids, env


def _key(key_file):
    if key_file is None:
        return None
    key = key_file.read_bytes()
    if len(key) < 32:
        raise ValueError("A receipt key requires at least 32 independent random bytes")
    return key


def _sign(payload, key):
    return {"payload": payload, "mac": mac(key, _encoded(payload), "sha256").hex() if key else None}


def _authenticate(receipt, key):
    if not isinstance(receipt, dict) or receipt.keys() != {"payload", "mac"} or not isinstance(receipt["mac"], str):
        raise ValueError("Missing authenticated evidence")
    if not compare_digest(receipt["mac"], _sign(receipt["payload"], key)["mac"]):
        raise ValueError("Evidence authentication failed")
    return receipt["payload"]


def _artifacts(directory, declared):
    return {"stdout.log": _file_digest(directory / "stdout.log"), "stderr.log": _file_digest(directory / "stderr.log"),
            **{f"artifacts/{name}": _file_digest(_within(directory / "artifacts", name)) for name in declared}}


def _run_task(repo, task, directory, tool, env):
    started = time.monotonic()
    (directory / "artifacts").mkdir(parents=True)
    runner_env = {**env, "ABC_TASK_OUTPUT": str(directory / "artifacts")}
    with (directory / "stdout.log").open("wb") as stdout, (directory / "stderr.log").open("wb") as stderr:
        if tool.get("status") == "missing":
            return "not_run", None, 0
        command = [tool["path"], *task["command"][1:]]
        with subprocess.Popen(command, cwd=repo, env=runner_env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                              start_new_session=(os.name != "nt")) as process:
            try:
                code = process.wait(timeout=task["timeout_seconds"])
                status = "passed" if code == 0 else "failed"
            except (KeyboardInterrupt, subprocess.TimeoutExpired) as interruption:
                if os.name == "nt":
                    try:
                        subprocess.run(["taskkill.exe", "/T", "/F", "/PID", str(process.pid)], env=env,
                                       capture_output=True, timeout=5, check=False)
                    finally:
                        process.kill()
                else:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
                code = None
                status = "cancelled" if isinstance(interruption, KeyboardInterrupt) else "timeout"
    return status, code, round((time.monotonic() - started) * 1000)


def _cache_hit(cache, destination, key, fingerprint):
    try:
        cached = _authenticate(read_json(cache / "result.json"), key)
        if cached["fingerprint"] != fingerprint or cached["status"] != "passed" or cached["artifacts"] != _artifacts(cache, []):
            return None
        (destination / "artifacts").mkdir(parents=True)
        for name in cached["artifacts"]:
            shutil.copyfile(cache / name, destination / name)
        return {**cached, "cached": True}
    except (OSError, ValueError, KeyError):
        return None


def execute(repo, plan_path, directory, domain, key_file=None, cache=None, target=None):
    if domain not in DOMAINS or (domain != "local" and (key_file or cache)) or (cache and not key_file):
        raise ValueError("Trust domain or cache configuration is unsupported")
    key = _key(key_file)
    plan = _fresh_plan(repo, plan_path)
    fingerprints, tools, env = _fingerprints(repo, plan, domain, target)
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    results = {}
    cacheable = []
    for name in _subset(plan, target):
        task = plan["tasks"][name]
        location = directory / "tasks" / _digest(name)
        fingerprint = fingerprints[name]
        cache_entry = cache / domain / fingerprint if cache and not task["outputs"] else None
        result = None
        if any(results[dependency]["status"] != "passed" for dependency in task["dependencies"]) or any(
            item["status"] == "cancelled" for item in results.values()
        ):
            result = {"status": "not_run", "exit_code": None, "elapsed_ms": 0, "artifacts": {}, "cached": False}
        elif cache_entry:
            result = _cache_hit(cache_entry, location, key, fingerprint)
        if result is None:
            try:
                status, code, elapsed = _run_task(repo, task, location, tools[task["command"][0]], env)
                artifacts = _artifacts(location, task["outputs"] if status == "passed" else [])
            except (OSError, ValueError) as error:
                status, code, elapsed, artifacts = "failed", None, 0, {}
                print(f"{name}: {error}", file=sys.stderr)
            result = {"status": status, "exit_code": code, "elapsed_ms": elapsed, "artifacts": artifacts, "cached": False}
        result.update({"fingerprint": fingerprint, "domain": domain})
        results[name] = result
        if cache_entry and result["status"] == "passed" and not result["cached"]:
            cacheable.append((cache_entry, location, result))

    same_inputs = False
    try:
        same_inputs = plan == _fresh_plan(repo, plan_path) and fingerprints == _fingerprints(repo, plan, domain, target)[0]
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Could not validate post-run inputs: {error}", file=sys.stderr)
    passed = bool(results) and same_inputs and all(item["status"] == "passed" for item in results.values())
    receipt = {"version": 1, "domain": domain, "plan_digest": _digest(plan), "head_revision": plan["head_revision"],
               "status": "passed" if passed else "failed", "inputs_unchanged": same_inputs, "results": results, "target": target}
    _write_json(directory / "receipt.json", _sign(receipt, key))
    if same_inputs:
        for entry, location, result in cacheable:
            try:
                entry.mkdir(parents=True, exist_ok=False)
                for artifact in result["artifacts"]:
                    shutil.copyfile(location / artifact, entry / artifact)
                _write_json(entry / "result.json", _sign(result, key))
            except OSError:
                # A cache write failure does not invalidate fresh evidence.
                continue
    return receipt


def verify_receipt(repo, plan_path, directory, domain, key_file, *, target=None):
    if domain != "local":
        raise ValueError("Only independently keyed local receipts can be accepted by this verifier")
    plan = _fresh_plan(repo, plan_path)
    fingerprints, _, _ = _fingerprints(repo, plan, domain, target)
    receipt = _authenticate(read_json(directory / "receipt.json"), _key(key_file))
    if (receipt["version"] != 1 or receipt["domain"] != domain or receipt["plan_digest"] != _digest(plan)
            or receipt["head_revision"] != plan["head_revision"] or receipt["status"] != "passed"
            or receipt["inputs_unchanged"] is not True or receipt["target"] != target or not fingerprints
            or receipt["results"].keys() != fingerprints.keys()):
        raise ValueError("Required evidence is missing, unsuccessful, stale, or out of trust scope")
    for name, fingerprint in fingerprints.items():
        result = receipt["results"][name]
        needed = _artifacts(directory / "tasks" / _digest(name), plan["tasks"][name]["outputs"])
        if (result["status"] != "passed" or result["exit_code"] != 0 or result["domain"] != domain
                or result["fingerprint"] != fingerprint or result["artifacts"] != needed):
            raise ValueError(f"Invalid evidence or artifacts for {name}")
    return {"status": "verified", "domain": domain, "task_count": len(fingerprints), "head_revision": plan["head_revision"]}
