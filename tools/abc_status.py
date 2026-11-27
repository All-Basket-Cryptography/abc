"""Validate status against the archived backlog and render a static explorer."""

from collections import Counter
from hashlib import sha256
from html import escape
import json


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)


def task_board(repo):
    source = repo / "docs/plan/abc"
    manifest = read_json(source / "HANDOFF-MANIFEST.json")
    for item in manifest["files"]:
        name = item["path"]
        if not isinstance(name, str) or not name or '/' in name or '\\' in name or name in {'.', '..'}:
            raise ValueError(f"Invalid handoff manifest path {name!r}")
        data = (source / name).read_bytes()
        if len(data) != item["size_bytes"] or sha256(data).hexdigest() != item["sha256"]:
            raise ValueError(f"Handoff file changed: {name}")

    backlog = read_json(source / "TASKS.json")
    updated = read_json(repo / "docs/status/tasks.json")
    tasks = {item["id"]: dict(item) for item in backlog["tasks"]}
    if len(tasks) != 40 or len(backlog["tasks"]) != len(tasks):
        raise ValueError("Expected 40 unique handoff tasks")
    if updated.keys() != {"schema_version", "tasks"} or updated["schema_version"] != 1:
        raise ValueError("Unsupported task status structure")
    for key, state in updated["tasks"].items():
        if key not in tasks or state.keys() != {"status", "evidence", "blockers"}:
            raise ValueError(f"Invalid task status entry {key}")
        status = state["status"]
        if status not in backlog["statuses"]:
            raise ValueError(f"Invalid task status {key}: {status}")
        if any(not isinstance(state[field], list) or any(not isinstance(value, str) or not value for value in state[field])
               for field in ("evidence", "blockers")):
            raise ValueError(f"Invalid evidence or blockers for {key}")
        if status == "done" and (not state["evidence"] or state["blockers"]):
            raise ValueError(f"Completed task {key} needs evidence and cannot have a blocker")
        if status == "blocked" and not state["blockers"]:
            raise ValueError(f"Blocked task {key} needs a specific blocker")
        for value in state["evidence"]:
            evidence = (repo / value).resolve()
            if not evidence.is_relative_to(repo.resolve()) or not evidence.is_file():
                raise ValueError(f"Missing or unsafe task evidence for {key}: {value}")
        tasks[key].update(state)

    checked = set()
    active = set()

    def visit(task_id):
        if task_id in active or task_id not in tasks:
            raise ValueError(f"Invalid dependency graph at {task_id}")
        if task_id in checked:
            return
        active.add(task_id)
        task = tasks[task_id]
        for dependency in task["depends_on"]:
            visit(dependency)
            if task["status"] == "done" and tasks[dependency]["status"] != "done":
                raise ValueError(f"Completed task {task_id} has an incomplete prerequisite {dependency}")
        active.remove(task_id)
        checked.add(task_id)

    for task_id in tasks:
        visit(task_id)
    for task in tasks.values():
        if task["status"] == "not_started" and all(tasks[dep]["status"] == "done" for dep in task["depends_on"]):
            task["status"] = "ready"

    return {"schema_version": 1, "counts": dict(Counter(task["status"] for task in tasks.values())),
            "milestones": {milestone: dict(Counter(task["status"] for task in tasks.values() if task["milestone"] == milestone))
                           for milestone in sorted({task["milestone"] for task in tasks.values()})},
            "tasks": list(tasks.values())}


def build_docs(repo, destination):
    from tools.abc_registry import validate

    board = task_board(repo)
    catalog = validate(repo)["records"]
    destination.mkdir(parents=True, exist_ok=True)
    rows = []
    for task in board["tasks"]:
        blockers = "; ".join(task["blockers"])
        rows.append("<tr>" + "".join(f"<td>{escape(value)}</td>" for value in
                                    (task["id"], task["milestone"], task["title"], task["status"], blockers)) + "</tr>")
    published = []
    for entry in catalog:
        if entry.get("record_type") in {"evidence-result", "release-set"}:
            continue
        details = escape(json.dumps(entry, ensure_ascii=True, indent=2))
        published.append(f'<details><summary>{escape(entry["id"])}</summary><pre>{details}</pre></details>')
    html = ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>ABC Explorer</title><style>body{font:1rem system-ui;max-width:75rem;margin:2rem auto;padding:0 1rem}"
            "table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.45rem;border-bottom:1px solid #aaa}"
            "pre{overflow:auto}summary{cursor:pointer;padding:.25rem 0}</style><h1>All-Basket Cryptography</h1>"
            "<h2>Task status</h2><table><thead><tr><th>Task</th><th>Milestone</th><th>Title</th><th>Status</th>"
            "<th>Blockers</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
            "<h2>Registry</h2><p>Evidence and release records require independent verification for assurance display.</p>"
            + "".join(published) + "</html>\n")
    (destination / "index.html").write_text(html, encoding="utf-8", newline="\n")
    (destination / "status.json").write_text(json.dumps(board, indent=2) + "\n", encoding="utf-8", newline="\n")
    return {"task_count": len(rows), "catalog_count": len(published), "output": str(destination)}
