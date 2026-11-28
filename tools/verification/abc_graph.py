"""Build deterministic dependency views and incremental verification plans."""

from collections import defaultdict, deque
from dataclasses import dataclass, field
import hashlib
from io import BytesIO
import json
import posixpath
import re
import subprocess
import tomllib


VERSION = 1
GATE = "abc-required"
EDGE_TYPES = {
    "imports", "calls", "implements", "wraps", "generated_from", "tests",
    "packages", "constrained_by",
}
DOC_KINDS = {"docs", "metadata"}
TEST_KINDS = {"test", "tests", "fuzz", "check", "compatibility"}
TOKEN = re.compile(r"[a-z][a-z0-9-]*\Z")
LEAN_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9']*(?:\.[A-Za-z_][A-Za-z_0-9']*)*\Z")
CARGO_SCOPES = ("dependencies", "dev-dependencies", "build-dependencies")


class GraphError(ValueError):
    """Invalid graph input or unavailable required revision."""


def _digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _git(repo, *args, allow_failure=False, payload=None):
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args], input=payload, capture_output=True, timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GraphError(f"git {args[0]} failed: {error}") from error
    if result.returncode:
        if allow_failure:
            return None
        raise GraphError(f"git {args[0]} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def _revision(repo, value, *, allow_failure=False):
    result = _git(repo, "rev-parse", "--verify", "--end-of-options", f"{value}^{{commit}}",
                  allow_failure=allow_failure)
    return result.decode().strip() if result is not None else None


def _subpath(path, prefix):
    return path == prefix or path.startswith(prefix + "/")


def _safe_path(path):
    return (isinstance(path, str) and bool(path)
            and not any(ord(char) < 32 or char in '\\:<>|"*?[]' for char in path)
            and not any(part.casefold() in {"", ".", "..", ".git"} for part in path.split("/")))


@dataclass
class _Snapshot:
    repo: object
    revision: str
    entries: dict
    metadata: dict = field(default_factory=dict)

    @classmethod
    def read(cls, repo, revision):
        entries = {}
        if revision == "WORKTREE":
            listing = _git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
            for raw in listing.split(b"\0")[:-1]:
                path = raw.decode()
                location = repo / path
                if location.is_symlink() or not location.resolve().is_relative_to(repo):
                    entries[path] = None
                elif location.is_file():
                    entries[path] = ""
        else:
            listing = _git(repo, "ls-tree", "-r", "-z", "--full-tree", revision)
            for raw in listing.split(b"\0")[:-1]:
                metadata, path = raw.split(b"\t", 1)
                mode, kind, oid = metadata.split()
                entries[path.decode()] = oid.decode() if kind == b"blob" and mode != b"120000" else None
        snapshot = cls(repo, revision, entries)
        if revision != "WORKTREE":
            snapshot.preload_metadata()
        return snapshot

    def preload_metadata(self):
        objects = sorted({oid for path, oid in self.entries.items() if oid and (
            posixpath.basename(path) in {"module.toml", "Cargo.toml"} or path.endswith(".lean")
            or path.startswith("registry/records/") and path.endswith(".json")
        )})
        if not objects:
            return
        payload = ("\n".join(objects) + "\n").encode("ascii")
        stream = BytesIO(_git(self.repo, "cat-file", "--batch", payload=payload))
        for oid in objects:
            header = stream.readline().decode("ascii").split()
            _require(len(header) == 3 and header[:2] == [oid, "blob"],
                     self.revision, f"Git metadata object is unavailable: {oid}")
            size = int(header[2])
            content = stream.read(size)
            _require(len(content) == size and stream.read(1) == b"\n",
                     self.revision, f"incomplete metadata blob: {oid}")
            self.metadata[oid] = content

    def content(self, path):
        if path not in self.entries or self.entries[path] is None:
            raise GraphError(f"expected a regular input at {path}")
        if self.revision == "WORKTREE":
            return (self.repo / path).read_bytes()
        oid = self.entries[path]
        return self.metadata[oid] if oid in self.metadata else _git(self.repo, "cat-file", "blob", oid)

    def text(self, path):
        try:
            return self.content(path).decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise GraphError(f"{path}: expected UTF-8") from error

    def toml(self, path):
        try:
            return tomllib.loads(self.text(path))
        except tomllib.TOMLDecodeError as error:
            raise GraphError(f"{path}: {error}") from error


def _require(condition, context, message):
    if not condition:
        raise GraphError(f"{context}: {message}")


def _strings(data, field, context, *, paths=False):
    values = data.get(field, [])
    valid = _safe_path if paths else lambda value: isinstance(value, str) and bool(value)
    _require(isinstance(values, list) and all(valid(value) for value in values),
             context, f"{field} must be an array of {'repository-relative paths' if paths else 'strings'}")
    _require(len(set(values)) == len(values), context, f"duplicate entry in {field}")
    return values


def _token(value):
    return isinstance(value, str) and TOKEN.fullmatch(value) is not None


def _task_ref(module, value):
    return value if ":" in value else f"{module}:{value}"


def _load_modules(snapshot):
    modules, tasks = {}, {}
    for path in sorted(snapshot.entries):
        if posixpath.basename(path) != "module.toml" or path.startswith("tools/tests/fixtures/"):
            continue
        data = snapshot.toml(path)
        allowed = {"schema_version", "id", "owner", "source", "owned_paths", "shared_inputs",
                   "cargo_manifests", "lean_sources", "lean_external_imports", "dependencies", "tasks"}
        _require(not set(data) - allowed, path, f"unknown fields {sorted(set(data) - allowed)}")
        module = data.get("id")
        _require(type(data.get("schema_version")) is int and data["schema_version"] == VERSION and _token(module),
                 path, "expected schema_version 1 and a valid id")
        _require(module not in modules, path, f"duplicate module id {module}")
        for field in ("owner", "source"):
            _require(field not in data or isinstance(data[field], str) and data[field],
                     path, f"{field} must be a nonempty string")
        owned_paths = _strings(data, "owned_paths", path, paths=True)
        shared_inputs = _strings(data, "shared_inputs", path, paths=True)
        manifests = _strings(data, "cargo_manifests", path, paths=True)
        for field in ("lean_sources", "lean_external_imports"):
            mapping = data.get(field, {})
            _require(isinstance(mapping, dict) and all(
                LEAN_NAME.fullmatch(prefix) and _safe_path(root) for prefix, root in mapping.items()
            ), path, f"{field} must map Lean module prefixes to repository-relative paths")
        dependencies = data.get("dependencies", [])
        _require(isinstance(dependencies, list) and all(
            isinstance(edge, dict) and set(edge) == {"module", "type"}
            and _token(edge["module"]) and isinstance(edge["type"], str) and edge["type"] in EDGE_TYPES
            for edge in dependencies
        ), path, "dependencies must contain module ids and recognized dependency types")
        definitions = data.get("tasks")
        _require(bool(owned_paths) and isinstance(definitions, dict) and bool(definitions),
                 path, "owned_paths and tasks must be nonempty")
        modules[module] = {
            "manifest": path, "owned_paths": sorted(set([path, *owned_paths, *manifests])),
            "shared_inputs": sorted(shared_inputs), "cargo_manifests": sorted(manifests),
            "lean_sources": data.get("lean_sources", {}),
            "lean_external_imports": data.get("lean_external_imports", {}),
            "declared_dependencies": dependencies,
        }
        for name, task in definitions.items():
            context = f"{path} task {name}"
            _require(_token(name) and isinstance(task, dict), context, "invalid task definition")
            fields = {"command", "dependencies", "inputs", "outputs", "kind", "timeout_seconds",
                      "features", "target", "tools", "always"}
            _require(not set(task) - fields, context, f"unknown fields {sorted(set(task) - fields)}")
            command = task.get("command")
            _require(isinstance(command, list) and command
                     and all(isinstance(arg, str) and arg and "\x00" not in arg for arg in command),
                     context, "command must be a nonempty argument array")
            timeout = task.get("timeout_seconds", 120)
            kind = task.get("kind", "check")
            target = task.get("target", "host")
            _require(type(timeout) is int and 1 <= timeout <= 3600, context, "invalid timeout_seconds")
            _require(_token(kind) and isinstance(target, str) and bool(target), context, "invalid kind or target")
            always = task.get("always", False)
            _require(type(always) is bool, context, "always must be boolean")
            task_id = f"{module}:{name}"
            references = [_task_ref(module, dep) for dep in _strings(task, "dependencies", context)]
            _require(all(len(dep.split(":")) == 2 and all(_token(part) for part in dep.split(":")) for dep in references),
                     context, "invalid task dependency reference")
            tasks[task_id] = {
                "module": module, "command": command, "dependencies": sorted(set(references)),
                "declared_inputs": sorted(_strings(task, "inputs", context, paths=True)),
                "outputs": sorted(_strings(task, "outputs", context, paths=True)), "kind": kind,
                "timeout_seconds": timeout, "features": sorted(_strings(task, "features", context)),
                "target": target, "tools": sorted(_strings(task, "tools", context) or [command[0]]), "always": always,
            }
    _require(bool(modules), "module graph", "no module.toml files found")
    return modules, tasks


def _expand(snapshot, prefixes, context):
    paths = set()
    for prefix in prefixes:
        matches = {path for path in snapshot.entries if _subpath(path, prefix)}
        _require(bool(matches), context, f"declared input does not exist: {prefix}")
        _require(all(snapshot.entries[path] is not None for path in matches),
                 context, f"input includes a symlink or non-file entry: {prefix}")
        paths.update(matches)
    return paths


def _owners(snapshot, modules):
    declared, owners = {}, {}
    for module, info in modules.items():
        for prefix in info["owned_paths"]:
            _require(prefix not in declared, info["manifest"],
                     f"ownership of {prefix} is already declared by {declared.get(prefix)}")
            _expand(snapshot, [prefix], info["manifest"])
            declared[prefix] = module
    for path in sorted(snapshot.entries):
        location = path
        while location:
            if location in declared:
                owners[path] = declared[location]
                break
            location = posixpath.dirname(location)
    for module, info in modules.items():
        _require(owners[info["manifest"]] == module, info["manifest"], "module must own its manifest")
    return owners


def _edge(consumer, required, relation, source):
    return {"consumer": consumer, "prerequisite": required, "type": relation, "source": source}


def _unique_edges(edges):
    fields = ("consumer", "prerequisite", "type", "source")
    keyed = {tuple(edge[field] for field in fields): edge for edge in edges}
    return [keyed[key] for key in sorted(keyed)]


def _cargo_manifest_edges(snapshot, owners, modules):
    paths = {path for path in snapshot.entries if posixpath.basename(path) == "Cargo.toml"
             and not path.startswith("tools/tests/fixtures/")}
    tables = {path: snapshot.toml(path) for path in sorted(paths)}
    workspaces = {path: data["workspace"] for path, data in tables.items() if "workspace" in data}
    edges, auxiliary, diagnostics = [], defaultdict(set), []

    def workspace_of(path, data):
        package = data.get("package", {})
        if isinstance(package, dict) and "workspace" in package:
            return posixpath.normpath(posixpath.join(posixpath.dirname(path), package["workspace"], "Cargo.toml"))
        directory = posixpath.dirname(path)
        while True:
            candidate = posixpath.join(directory, "Cargo.toml")
            if candidate in workspaces or not directory:
                return candidate if candidate in workspaces else None
            directory = posixpath.dirname(directory)

    def path_edge(consumer, source, name, dependency, relation):
        if not isinstance(dependency, dict) or "path" not in dependency:
            return
        relative = dependency["path"]
        _require(isinstance(relative, str) and not relative.startswith(('/', '\\')) and ':' not in relative,
                 source, f"invalid Cargo path for {name}")
        destination = posixpath.normpath(posixpath.join(posixpath.dirname(source),
                                                      relative.replace("\\", "/"), "Cargo.toml"))
        _require(_safe_path(destination) and destination in tables, source,
                 f"Cargo dependency {name} resolves outside the declared workspace or is missing: {destination}")
        provider = owners.get(destination)
        _require(provider is not None, source, f"unowned Cargo dependency {destination}")
        if consumer != provider:
            edges.append(_edge(consumer, provider, relation, f"{source} dependency {name}"))

    for path, data in tables.items():
        consumer = owners.get(path)
        if not consumer:
            diagnostics.append(f"Cargo manifest has no owner: {path}")
            continue
        workspace = workspace_of(path, data)
        _require(workspace is None or workspace in workspaces, path, "Cargo workspace manifest is missing")
        auxiliary[consumer].update(item for item in (path, workspace) if item)
        root = posixpath.dirname(workspace or path)
        for name in ("Cargo.lock", ".cargo/config", ".cargo/config.toml", "rust-toolchain", "rust-toolchain.toml"):
            candidate = posixpath.join(root, name)
            if candidate in snapshot.entries:
                auxiliary[consumer].add(candidate)
        workspace_table = workspaces.get(workspace, {})
        _require(isinstance(workspace_table, dict), path, "Cargo workspace must be a table")
        inherited = workspace_table.get("dependencies", {})
        _require(isinstance(inherited, dict), path, "Cargo workspace dependencies must be a table")
        target_tables = data.get("target", {})
        _require(isinstance(target_tables, dict), path, "Cargo target dependencies must be tables")
        for section in (data, *target_tables.values()):
            _require(isinstance(section, dict), path, "Cargo target configuration must be a table")
            for field in CARGO_SCOPES:
                deps = section.get(field, {})
                _require(isinstance(deps, dict), path, f"Cargo {field} must be a table")
                for name, dep in deps.items():
                    relation = "tests" if field == "dev-dependencies" else "imports"
                    if isinstance(dep, dict) and dep.get("workspace") is True:
                        _require(name in inherited, path, f"Cargo workspace dependency is missing: {name}")
                        path_edge(consumer, workspace, name, inherited[name], relation)
                    else:
                        path_edge(consumer, path, name, dep, relation)
        root_data = tables[workspace or path]
        patch = root_data.get("patch", {})
        replace = root_data.get("replace", {})
        _require(isinstance(patch, dict) and isinstance(replace, dict), path, "invalid Cargo patch or replace table")
        for entries in (*patch.values(), replace):
            _require(isinstance(entries, dict), path, "invalid Cargo patch entries")
            for name, dep in entries.items():
                path_edge(consumer, workspace or path, name, dep, "imports")
    return edges, auxiliary, diagnostics


def _lean_header(text, path):
    """Read import commands from the module header, skipping nested comments."""
    imports = []
    depth = 0
    for line in text.splitlines():
        clean = []
        index = 0
        while index < len(line):
            token = line[index:index + 2]
            if token == "/-":
                depth += 1
                clean.append(" ")
                index += 2
            elif depth and token == "-/":
                depth -= 1
                index += 2
            elif not depth and token == "--":
                break
            else:
                if not depth:
                    clean.append(line[index])
                index += 1
        header = "".join(clean).strip()
        if not header or header in {"module", "prelude"}:
            continue
        match = re.fullmatch(r"(?:(?:public|meta|private)\s+)*import(?:\s+(.*))?", header)
        if match is None:
            break
        names = (match.group(1) or "").split()
        if not names or not all(LEAN_NAME.fullmatch(name) for name in names):
            return imports, f"Lean import syntax needs native dependency validation: {path}"
        imports.extend(names)
    if depth:
        return imports, f"unterminated Lean header comment: {path}"
    return imports, None


def _lean_edges(snapshot, owners, modules):
    prefixes, names, auxiliary = {}, {}, defaultdict(set)
    edges, diagnostics = [], []
    paths = [path for path in sorted(snapshot.entries) if path.endswith(".lean")
             and not path.startswith("tools/tests/fixtures/") and snapshot.entries[path] is not None]
    for module, info in modules.items():
        for prefix, dependency in info["lean_external_imports"].items():
            _expand(snapshot, [dependency], info["manifest"])
        for prefix, root in info["lean_sources"].items():
            _require(prefix not in prefixes or prefixes[prefix] == root, info["manifest"],
                     f"conflicting Lean source roots for {prefix}")
            prefixes[prefix] = root
            _require(any(_subpath(path, root) for path in paths), info["manifest"],
                     f"Lean source root contains no Lean files: {root}")
            for path in paths:
                if not path.startswith(root + "/"):
                    continue
                name = path[len(root) + 1:-len(".lean")].replace("/", ".")
                if name == prefix or name.startswith(prefix + "."):
                    _require(name not in names or names[name] == path, info["manifest"],
                             f"ambiguous Lean module {name}")
                    names[name] = path
    external = {"Init", "Lean", "Std", "Lake"}
    for path in paths:
        consumer = owners.get(path)
        if not consumer:
            diagnostics.append(f"Lean source has no owner: {path}")
            continue
        directory = posixpath.dirname(path)
        while True:
            for marker in ("lean-toolchain", "lakefile.lean", "lakefile.toml", "lake-manifest.json"):
                candidate = posixpath.join(directory, marker)
                if candidate in snapshot.entries:
                    auxiliary[consumer].add(candidate)
            if not directory:
                break
            directory = posixpath.dirname(directory)
        imports, diagnostic = _lean_header(snapshot.text(path), path)
        if diagnostic:
            diagnostics.append(diagnostic)
        for name in imports:
            imported = names.get(name)
            if imported is None:
                declarations = modules[consumer]["lean_external_imports"]
                matching = [prefix for prefix in declarations if name == prefix or name.startswith(prefix + ".")]
                if matching:
                    dependency = declarations[max(matching, key=len)]
                    auxiliary[consumer].update(_expand(snapshot, [dependency], path))
                elif name.split(".", 1)[0] not in external:
                    diagnostics.append(f"unresolved Lean import {name} in {path}")
                continue
            provider = owners.get(imported)
            _require(provider is not None, path, f"Lean import {name} resolves to unowned source {imported}")
            if consumer != provider:
                edges.append(_edge(consumer, provider, "imports", f"{path} imports {name}"))
    return edges, auxiliary, diagnostics


def _topological(tasks):
    visited, active, ordered = set(), [], []

    def visit(task_id):
        if task_id in active:
            cycle = active[active.index(task_id):] + [task_id]
            raise GraphError(f"task dependency cycle: {' -> '.join(cycle)}")
        if task_id in visited:
            return
        _require(task_id in tasks, "task graph", f"unknown task dependency: {task_id}")
        active.append(task_id)
        for dependency in tasks[task_id]["dependencies"]:
            visit(dependency)
        active.pop()
        visited.add(task_id)
        ordered.append(task_id)

    for task_id in sorted(tasks):
        visit(task_id)
    return ordered


def _registry_views(snapshot):
    nodes, links = {}, defaultdict(list)

    def refs(value):
        if isinstance(value, dict):
            for key, entry in value.items():
                if key.endswith("_ref") and isinstance(entry, str):
                    yield key[:-4], entry
                elif key.endswith("_refs") and isinstance(entry, list):
                    for ref in entry:
                        if isinstance(ref, str):
                            yield key[:-5], ref
                else:
                    yield from refs(entry)
        elif isinstance(value, list):
            for entry in value:
                yield from refs(entry)

    for path in sorted(snapshot.entries):
        if not path.startswith("registry/records/") or not path.endswith(".json"):
            continue
        try:
            records = json.loads(snapshot.text(path))
        except ValueError as error:
            raise GraphError(f"{path}: invalid registry JSON: {error}") from error
        for record in records if isinstance(records, list) else [records]:
            _require(isinstance(record, dict) and isinstance(record.get("id"), str)
                     and isinstance(record.get("record_type"), str), path, "expected a typed registry record")
            identifier, kind = record["id"], record["record_type"]
            _require(identifier not in nodes, path, f"duplicate registry id {identifier}")
            nodes[identifier] = {"kind": kind, "source": path}
            for relation, prerequisite in refs(record):
                links[identifier].append(_edge(identifier, prerequisite, relation, path))
    evidence_types = {"evidence-request", "evidence-result", "release-set"}
    evidence, knowledge = {"nodes": {}, "edges": []}, {"nodes": {}, "edges": []}
    for identifier, metadata in nodes.items():
        view = evidence if metadata["kind"] in evidence_types else knowledge
        view["nodes"][identifier] = metadata
        for link in links[identifier]:
            prerequisite = link["prerequisite"]
            _require(prerequisite in nodes, metadata["source"], f"invalid registry reference {prerequisite}")
            view["nodes"][prerequisite] = nodes[prerequisite]
            view["edges"].append(link)
    for view in (knowledge, evidence):
        view["edges"] = _unique_edges(view["edges"])
    return knowledge, evidence


def _is_global(path):
    return (path.startswith((".github/", "registry/policy/", "registry/schemas/", "tools/verification/", "tools/abc_"))
            or path in {"abc.py", ".gitattributes", ".gitignore"})


def _is_documentation(path):
    return (path.lower().endswith((".md", ".rst")) or path.startswith("registry/")) and not _is_global(path)


def _transitive(start, adjacency):
    seen = set(start)
    frontier = deque(start)
    while frontier:
        item = frontier.popleft()
        for dependency in sorted(adjacency.get(item, ())):
            if dependency not in seen:
                frontier.append(dependency)
                seen.add(dependency)
    return seen


def _assemble(snapshot):
    modules, tasks = _load_modules(snapshot)
    owners = _owners(snapshot, modules)
    edges = []
    for consumer, module in modules.items():
        for edge in module.pop("declared_dependencies"):
            provider = edge["module"]
            _require(provider in modules, module["manifest"], f"unknown module dependency: {provider}")
            edges.append(_edge(consumer, provider, edge["type"], module["manifest"]))
    cargo_edges, cargo_inputs, cargo_diagnostics = _cargo_manifest_edges(snapshot, owners, modules)
    lean_edges, lean_inputs, lean_diagnostics = _lean_edges(snapshot, owners, modules)
    module_edges = _unique_edges([*edges, *cargo_edges, *lean_edges])
    order = _topological(tasks)
    prerequisites, dev_prerequisites = defaultdict(set), defaultdict(set)
    for edge in module_edges:
        mapping = dev_prerequisites if edge["type"] == "tests" else prerequisites
        mapping[edge["consumer"]].add(edge["prerequisite"])
    global_inputs = {path for path in snapshot.entries if _is_global(path)}
    _require(all(snapshot.entries[path] is not None for path in global_inputs),
             "module graph", "global inputs include a symlink or non-file entry")
    module_inputs, module_shared, owners_inputs = {}, {}, defaultdict(set)
    for path, owner in owners.items():
        owners_inputs[owner].add(path)
    for name, module in modules.items():
        shared = _expand(snapshot, module["shared_inputs"], module["manifest"])
        shared.update(cargo_inputs[name] | lean_inputs[name])
        module["inputs"] = sorted(shared | owners_inputs[name])
        module_shared[name] = shared
        module_inputs[name] = shared | owners_inputs[name]
    task_consumers = defaultdict(list)
    for task_id in order:
        task = tasks[task_id]
        scope = {task["module"]}
        extra = _expand(snapshot, task.pop("declared_inputs"), task_id)
        if task["kind"] not in DOC_KINDS:
            if task["kind"] in TEST_KINDS:
                scope.update(dev_prerequisites[task["module"]])
            scope = _transitive(scope, prerequisites)
        inputs = set.union(set(), *(module_inputs[item] for item in scope))
        if task["kind"] not in DOC_KINDS:
            inputs = {path for path in inputs if not _is_documentation(path)}
            extra.update(set.union(set(), *(module_shared[item] for item in scope)))
        for path in sorted(extra):
            task_consumers[path].append(task_id)
        inputs.update(extra | global_inputs)
        for dependency in task["dependencies"]:
            inputs.update(tasks[dependency]["inputs"])
        _require(all(snapshot.entries[path] is not None for path in inputs), task_id, "non-file input")
        task["inputs"] = sorted(inputs)
    knowledge, evidence = _registry_views(snapshot)
    graph = {
        "graph_version": VERSION, "modules": modules, "owners": owners, "module_edges": module_edges,
        "tasks": tasks, "topological_order": order, "knowledge_graph": knowledge, "evidence_graph": evidence,
        "task_edges": [_edge(task_id, dep, "requires", modules[task["module"]]["manifest"])
                       for task_id, task in sorted(tasks.items()) for dep in task["dependencies"]],
        "task_consumers": dict(sorted(task_consumers.items())),
        "diagnostics": sorted(set(cargo_diagnostics + lean_diagnostics)),
        "unowned_paths": sorted(snapshot.entries.keys() - owners.keys()),
    }
    return {**graph, "revision": snapshot.revision, "graph_digest": _digest(graph)}


def build_graph(repo, revision="WORKTREE"):
    """Return the graph at a Git commit or the local checkout."""
    repo = repo.resolve()
    resolved = revision if revision == "WORKTREE" else _revision(repo, revision)
    return _assemble(_Snapshot.read(repo, resolved))


def _changes(repo, base, head):
    if base is None:
        return [{"status": "A", "path": path} for path in sorted(head.entries)]
    args = ["diff", "--name-status", "-z", "--no-ext-diff", "--no-textconv",
            "--find-renames", "--find-copies", base.revision]
    if head.revision != "WORKTREE":
        args.append(head.revision)
    entries = _git(repo, *args, "--").decode().split("\0")[:-1]
    records = []
    cursor = iter(entries)
    for status in cursor:
        path = next(cursor)
        if status.startswith(("R", "C")):
            records.append({"status": status, "old_path": path, "path": next(cursor)})
        else:
            records.append({"status": status, "path": path})
    if head.revision == "WORKTREE":
        reported = {record["path"] for record in records}
        records.extend({"status": "A", "path": path}
                       for path in head.entries.keys() - base.entries.keys() - reported)
    return sorted(records, key=lambda item: (item["path"], item["status"]))


def _base_revision(repo, base, head, use_merge_base, fallback):
    if base is None:
        fallback.append("no base revision specified; full head verification required")
        return None
    resolved = _revision(repo, base, allow_failure=True)
    if not resolved:
        fallback.append(f"base revision {base!r} unavailable; full head verification required")
        return None
    if use_merge_base:
        committed_head = _revision(repo, "HEAD", allow_failure=True) if head == "WORKTREE" else head
        result = _git(repo, "merge-base", "--all", resolved, committed_head, allow_failure=True) if committed_head else None
        merge_bases = result.decode().splitlines() if result else []
        if len(merge_bases) != 1:
            fallback.append("unique merge base unavailable; full head verification required")
            return None
        return merge_bases[0]
    return resolved


def _module_impact(base, head, changes, fallback):
    """Walk reverse module edges across both snapshots, keeping the shortest discovered reason."""
    affected, test_only, document_paths, explicit_tasks = {}, {}, [], {}
    reverse = defaultdict(list)
    graphs = [graph for graph in (base, head) if graph]
    for edge in _unique_edges(edge for graph in graphs for edge in graph["module_edges"]):
        reverse[edge["prerequisite"]].append(edge)

    def mark(owner, reason):
        if owner not in affected:
            affected[owner] = reason

    for change in changes:
        old_path = change.get("old_path", change["path"])
        new_path = change["path"]
        operation = change["status"][0]
        previous = [(base, old_path)] if base and operation not in {"A", "C"} else []
        upcoming = [(head, new_path)] if operation != "D" else []
        for graph, path in (*previous, *upcoming):
            trace = [{"status": change["status"], "path": path}]
            owner = graph["owners"].get(path)
            if not owner:
                fallback.append(f"changed path without an owner: {path}")
            for task in graph["task_consumers"].get(path, ()):
                explicit_tasks.setdefault(task, trace)
            if _is_global(path):
                fallback.append(f"global verification input changed: {path}")
            elif _is_documentation(path):
                document_paths.append(path)
            else:
                if owner:
                    mark(owner, trace)
                for consumer, definition in graph["modules"].items():
                    if consumer != owner and path in definition["inputs"]:
                        mark(consumer, [*trace, {"consumer": consumer, "type": "shared_input", "source": path}])

    base_keys = {_digest(edge): edge for edge in base["module_edges"]} if base else {}
    head_keys = {_digest(edge): edge for edge in head["module_edges"]}
    for key in sorted(base_keys.keys() ^ head_keys.keys()):
        edge = head_keys[key] if key in head_keys else base_keys[key]
        reason = [{"changed_edge": "added" if key in head_keys else "removed", **edge}]
        if edge["type"] == "tests":
            test_only.setdefault(edge["consumer"], reason)
        else:
            mark(edge["consumer"], reason)

    frontier = deque(affected)
    while frontier:
        prerequisite = frontier.popleft()
        for edge in reverse[prerequisite]:
            consumer = edge["consumer"]
            reason = [*affected[prerequisite], edge]
            if edge["type"] == "tests":
                test_only.setdefault(consumer, reason)
            elif consumer not in affected:
                mark(consumer, reason)
                frontier.append(consumer)
    return affected, test_only, sorted(set(document_paths)), explicit_tasks


def _task_impact(base, head, affected, test_only, doc_paths, explicit_tasks, fallback):
    tasks = head["tasks"]
    reverse = defaultdict(set)
    for graph in (base, head):
        if graph:
            for task_id, definition in graph["tasks"].items():
                for dependency in definition["dependencies"]:
                    reverse[dependency].add(task_id)

    reasons = {}
    for task_id, task in tasks.items():
        module, kind = task["module"], task["kind"]
        reason = explicit_tasks.get(task_id) or affected.get(module)
        if not reason and kind in TEST_KINDS:
            reason = test_only.get(module)
        if not reason and kind in DOC_KINDS and doc_paths:
            reason = [{"type": "documentation", "paths": doc_paths}]
        if not reason and fallback:
            reason = [{"type": "fallback", "reason": item} for item in fallback]
        if not reason and task["always"]:
            reason = [{"type": "always_required"}]
        if reason:
            reasons[task_id] = reason

    removed = sorted(base["modules"].keys() - head["modules"].keys()) if base else []
    if removed:
        compatible = [task_id for task_id, task in tasks.items() if task["kind"] == "compatibility"]
        _require(bool(compatible), "impact plan", "removed module requires a surviving compatibility task")
        for task_id in compatible:
            reasons.setdefault(task_id, []).append({"type": "deleted_modules", "modules": removed})

    removed_tasks = sorted(base["tasks"].keys() - tasks.keys()) if base else []
    frontier = deque([*reasons, *removed_tasks])
    departed = set(removed_tasks)
    while frontier:
        prerequisite = frontier.popleft()
        for consumer in sorted(reverse[prerequisite]):
            if consumer in reasons or consumer in departed:
                continue
            relation = {"type": "task_consumer", "consumer": consumer, "prerequisite": prerequisite}
            if consumer in tasks:
                reasons[consumer] = [*reasons.get(prerequisite, []), relation]
            else:
                departed.add(consumer)
            frontier.append(consumer)

    for consumer in reversed(head["topological_order"]):
        if consumer not in reasons:
            continue
        for prerequisite in tasks[consumer]["dependencies"]:
            edge = {"type": "task_prerequisite", "consumer": consumer, "prerequisite": prerequisite}
            reasons.setdefault(prerequisite, [*reasons[consumer], edge])
    return reasons, removed


def create_plan(repo, base=None, head="WORKTREE", *, merge_base=False):
    """Select affected tasks using the union of revisions and order only the surviving head DAG."""
    repo = repo.resolve()
    revision = head if head == "WORKTREE" else _revision(repo, head)
    fallback = []
    base_revision = _base_revision(repo, base, revision, merge_base, fallback)
    head_snapshot = _Snapshot.read(repo, revision)
    base_snapshot = _Snapshot.read(repo, base_revision) if base_revision else None
    head_graph = _assemble(head_snapshot)
    base_graph = None
    if base_snapshot:
        has_modules = any(posixpath.basename(path) == "module.toml" and not path.startswith("tools/tests/fixtures/")
                          for path in base_snapshot.entries)
        if has_modules:
            base_graph = _assemble(base_snapshot)
        else:
            fallback.append("base revision predates module manifests; full head verification required")
    changes = _changes(repo, base_snapshot, head_snapshot)
    for graph in (base_graph, head_graph):
        if graph:
            fallback.extend(graph["diagnostics"])
    affected, test_only, docs, explicit_tasks = _module_impact(base_graph, head_graph, changes, fallback)
    fallback = sorted(set(fallback))
    reasons, removed = _task_impact(base_graph, head_graph, affected, test_only, docs, explicit_tasks, fallback)
    selected = [task for task in head_graph["topological_order"] if task in reasons]
    selected_specs, content_digests = {}, {}
    for task in selected:
        definition = head_graph["tasks"][task]
        inputs = definition["inputs"]
        for path in inputs:
            if path not in content_digests:
                if revision == "WORKTREE":
                    content_digests[path] = "sha256:" + hashlib.sha256(head_snapshot.content(path)).hexdigest()
                else:
                    content_digests[path] = "git:" + head_snapshot.entries[path]
        selected_specs[task] = {**definition, "input_digest": _digest([(path, content_digests[path]) for path in inputs])}
    selected_modules = {spec["module"] for spec in selected_specs.values()}
    return {
        "planner_version": VERSION, "requested_base": base, "requested_head": head, "merge_base": merge_base,
        "base_revision": base_revision, "head_revision": revision, "changed_paths": changes,
        "graph_digest": head_graph["graph_digest"],
        "base_graph_digest": base_graph["graph_digest"] if base_graph else None,
        "affected_nodes": sorted(set(affected) | set(test_only) | selected_modules | set(removed)),
        "selected_tasks": selected, "tasks": selected_specs,
        "github_matrix": {"include": [{"task": task} for task in selected]},
        "reason_paths": {task: reasons[task] for task in selected},
        "excluded_reason": {task: "no affected input or task dependency" for task in head_graph["tasks"] if task not in reasons},
        "tombstones": [{"module": name, "manifest": base_graph["modules"][name]["manifest"]} for name in removed],
        "cache_candidates": [], "fallback_reason": fallback, "required_gate": GATE,
    }
