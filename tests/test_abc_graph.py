"""Exercise the graph and planner against committed Git histories."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools.abc_graph import GraphError, build_graph, create_plan
from tools.abc_ci import BASELINE_ENTRY, _plan as ci_plan
from tools.abc_runner import VERIFIER_INPUTS


class PlannerTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "core.autocrlf", "false")

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=ABC fixture",
                                 "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                                 "-c", "core.hooksPath=.unused-fixture-hooks", *args],
                                check=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()

    def write(self, path, text):
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8", newline="\n")

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def module(self, name, *, directory=None, kind="check", extra="", task_extra="", owned=None):
        directory = directory or name
        self.write(f"{directory}/module.toml", f"""schema_version = 1
id = {json.dumps(name)}
owned_paths = {json.dumps(owned or [directory])}
{extra}
[tasks.check]
kind = {json.dumps(kind)}
command = ["python", "-V"]
{task_extra}
""")

    def crate(self, name, dependencies="", *, extra=""):
        self.module(name, extra=extra)
        self.write(f"{name}/Cargo.toml", f"""[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
{dependencies}
""")
        self.write(f"{name}/src/lib.rs", "pub fn probe() {}\n")

    def baseline(self):
        self.module("status", kind="docs", directory="docs", owned=["docs", "registry"])
        self.module("compat", kind="compatibility")
        self.write("registry/readme.md", "Catalog fixture.\n")
        self.crate("sha256", extra='lean_sources = { Abc = "sha256/formal" }')
        self.crate("hmac", '[dependencies]\nhash = { package = "sha256", path = "../sha256" }')
        self.crate("hkdf", '[dependencies]\nhmac = { path = "../hmac" }')
        self.crate("binding", '[dependencies]\nhkdf = { path = "../hkdf" }')
        self.crate("sha3", extra='lean_sources = { Abc3 = "sha3/formal" }')
        self.module("foundation", kind="proof", extra='lean_sources = { Foundation = "foundation/formal" }')
        self.write("foundation/formal/Foundation/Bits.lean", "def exampleWidth := 8\n")
        self.write("sha256/formal/Abc/Spec.lean", "-- import NotReal\n/- /- nested -/ -/\nimport Foundation.Bits\n")
        self.write("sha3/formal/Abc3/Spec.lean", "import Foundation.Bits -- real dependency\n")
        return self.commit("baseline")

    def test_cargo_transitive_impact_and_reasons(self):
        base = self.baseline()
        self.write("sha256/src/lib.rs", "pub fn probe() -> u8 { 2 }\n")
        head = self.commit("update sha256")
        plan = create_plan(self.repo, base, head)
        self.assertEqual(set(plan["selected_tasks"]), {"sha256:check", "hmac:check", "hkdf:check", "binding:check"})
        self.assertEqual(plan["reason_paths"]["binding:check"][-1]["prerequisite"], "hkdf")
        self.assertIn("sha256/src/lib.rs", plan["tasks"]["binding:check"]["inputs"])
        self.assertEqual(plan, create_plan(self.repo, base, head))

    def test_independent_sha3_and_lean_foundation(self):
        base = self.baseline()
        self.write("sha3/src/lib.rs", "pub fn probe() -> u8 { 3 }\n")
        head = self.commit("independent change")
        self.assertEqual(create_plan(self.repo, base, head)["selected_tasks"], ["sha3:check"])
        self.write("foundation/formal/Foundation/Bits.lean", "def exampleWidth := 16\n")
        final = self.commit("change common Lean import")
        plan = create_plan(self.repo, head, final)
        self.assertTrue({"foundation:check", "sha3:check", "sha256:check"} <= set(plan["selected_tasks"]))
        self.assertFalse(plan["fallback_reason"])

    def test_docs_do_not_recheck_algorithm_modules(self):
        base = self.baseline()
        self.write("sha256/README.md", "New module documentation.\n")
        self.write("registry/readme.md", "New citation.\n")
        head = self.commit("docs only")
        plan = create_plan(self.repo, base, head)
        self.assertEqual(plan["selected_tasks"], ["status:check"])
        self.assertFalse(plan["fallback_reason"])

    def test_worktree_and_missing_base_fail_conservative(self):
        base = self.baseline()
        self.write("unowned.txt", "Unclassified content.\n")
        plan = create_plan(self.repo, base)
        self.assertIn({"status": "A", "path": "unowned.txt"}, plan["changed_paths"])
        self.assertIn("changed path without an owner: unowned.txt", plan["fallback_reason"])
        self.assertEqual(plan["selected_tasks"], build_graph(self.repo)["topological_order"])
        plan = create_plan(self.repo, "unknown-base", base)
        self.assertIsNone(plan["base_revision"])
        self.assertIn("unavailable", plan["fallback_reason"][0])
        self.assertEqual(plan["selected_tasks"], build_graph(self.repo, base)["topological_order"])

    def test_worktree_content_change_invalidates_only_matching_input_digests(self):
        base = self.baseline()
        self.write("sha3/src/lib.rs", "pub fn first() {}\n")
        first = create_plan(self.repo, base)
        self.write("sha3/src/lib.rs", "pub fn second() {}\n")
        second = create_plan(self.repo, base)
        self.assertEqual(first["graph_digest"], second["graph_digest"])
        self.assertEqual(first["selected_tasks"], ["sha3:check"])
        self.assertNotEqual(first["tasks"]["sha3:check"]["input_digest"], second["tasks"]["sha3:check"]["input_digest"])

    def test_removal_schedules_compatibility_and_surviving_consumers(self):
        base = self.baseline()
        self.git("rm", "-r", "hmac")
        self.write("hkdf/Cargo.toml", '[package]\nname="hkdf"\nversion="0.1.0"\nedition="2021"\n')
        head = self.commit("remove module")
        plan = create_plan(self.repo, base, head)
        self.assertEqual(plan["tombstones"], [{"module": "hmac", "manifest": "hmac/module.toml"}])
        self.assertEqual(set(plan["selected_tasks"]), {"hkdf:check", "binding:check", "compat:check"})
        self.assertEqual(plan["reason_paths"]["compat:check"][-1]["type"], "deleted_modules")

    def test_rename_tracks_old_owner_and_new_owner(self):
        base = self.baseline()
        self.git("mv", "sha256/src/lib.rs", "sha3/relocated.rs")
        head = self.commit("rename across ownership boundaries")
        plan = create_plan(self.repo, base, head)
        self.assertEqual(plan["changed_paths"], [{"status": "R100", "old_path": "sha256/src/lib.rs",
                                                  "path": "sha3/relocated.rs"}])
        self.assertIn("binding:check", plan["selected_tasks"])
        self.assertIn("sha3:check", plan["selected_tasks"])

    def test_cyclic_union_can_have_an_acyclic_head(self):
        self.module("a", extra='dependencies = [{module="b",type="calls"}]', task_extra='dependencies = ["b:check"]')
        self.module("b")
        base = self.commit("a consumes b")
        self.module("a")
        self.module("b", extra='dependencies = [{module="a",type="calls"}]', task_extra='dependencies = ["a:check"]')
        head = self.commit("b consumes a")
        self.assertEqual(create_plan(self.repo, base, head)["selected_tasks"], ["a:check", "b:check"])

    def test_registry_cycle_and_evidence_views(self):
        self.module("status", kind="metadata", owned=["status", "registry"])
        self.write("registry/one.json", json.dumps({"id": "abc:algorithm:one", "record_type": "algorithm",
                                                  "alias_of_ref": "abc:algorithm:two"}))
        self.write("registry/two.json", json.dumps({"id": "abc:algorithm:two", "record_type": "algorithm",
                                                  "alias_of_ref": "abc:algorithm:one"}))
        self.write("registry/proof.json", json.dumps({"id": "abc:evidence-result:one", "record_type": "evidence-result",
                                                    "subject_ref": "abc:algorithm:one"}))
        graph = build_graph(self.repo)
        self.assertEqual(len(graph["knowledge_graph"]["edges"]), 2)
        self.assertEqual(graph["evidence_graph"]["edges"][0]["type"], "subject")
        self.assertEqual(graph["topological_order"], ["status:check"])

    def test_true_task_cycle_and_invalid_references_are_rejected(self):
        self.module("a", task_extra='dependencies = ["b:check"]')
        self.module("b", task_extra='dependencies = ["a:check"]')
        with self.assertRaisesRegex(GraphError, "task dependency cycle: a:check -> b:check -> a:check"):
            build_graph(self.repo)
        self.module("b", task_extra='dependencies = ["missing"]')
        with self.assertRaisesRegex(GraphError, "unknown task dependency: b:missing"):
            build_graph(self.repo)

    def test_missing_declared_paths_and_overlapping_exact_ownership_fail(self):
        self.module("a", task_extra='inputs = ["missing"]')
        with self.assertRaisesRegex(GraphError, "declared input does not exist: missing"):
            build_graph(self.repo)
        self.module("a")
        self.module("b", owned=["a"])
        with self.assertRaisesRegex(GraphError, "ownership of a is already declared"):
            build_graph(self.repo)

    def test_inherited_target_dependencies_and_lock_inputs(self):
        self.module("cargo-workspace", owned=["Cargo.toml", "Cargo.lock", "cargo-workspace"])
        self.write("Cargo.toml", '[workspace]\nmembers=["lib", "bin"]\n[workspace.dependencies]\nlib={path="lib"}\n')
        self.write("Cargo.lock", "version = 4\n")
        self.crate("lib")
        self.crate("bin", '[target.\'cfg(unix)\'.dev-dependencies]\nlib = { workspace = true }')
        base = self.commit("workspace dependency")
        graph = build_graph(self.repo, base)
        self.assertIn({"consumer": "bin", "prerequisite": "lib", "type": "tests",
                       "source": "Cargo.toml dependency lib"}, graph["module_edges"])
        self.assertIn("Cargo.lock", graph["tasks"]["bin:check"]["inputs"])
        self.write("Cargo.lock", "version = 4\n# lock update\n")
        head = self.commit("lock changes all its consumers")
        self.assertEqual(set(create_plan(self.repo, base, head)["selected_tasks"]),
                         {"bin:check", "lib:check", "cargo-workspace:check"})

    def test_feature_and_policy_changes_have_explicit_reasons(self):
        base = self.baseline()
        self.module("sha3", extra='lean_sources = { Abc3 = "sha3/formal" }', task_extra='features = ["portable"]')
        head = self.commit("sha3 feature")
        plan = create_plan(self.repo, base, head)
        self.assertEqual(plan["selected_tasks"], ["sha3:check"])
        self.assertEqual(plan["tasks"]["sha3:check"]["features"], ["portable"])
        self.write("security/policy.md", "Update assurance trust policy.\n")
        final = self.commit("global trust policy change")
        plan = create_plan(self.repo, head, final)
        self.assertEqual(plan["selected_tasks"], build_graph(self.repo, final)["topological_order"])
        self.assertIn("global verification input changed: security/policy.md", plan["fallback_reason"])
        self.assertIn("security/policy.md", plan["tasks"]["sha256:check"]["inputs"])

    def test_merge_base_uses_branch_point(self):
        base = self.baseline()
        self.git("switch", "-qc", "topic")
        self.write("sha3/src/lib.rs", "pub fn topic() {}\n")
        topic = self.commit("topic change")
        self.git("switch", "-q", "main")
        self.write("sha256/src/lib.rs", "pub fn mainline() {}\n")
        self.commit("mainline change")
        plan = create_plan(self.repo, "main", topic, merge_base=True)
        self.assertEqual(plan["base_revision"], base)
        self.assertEqual(plan["selected_tasks"], ["sha3:check"])

    def test_real_sha2_sha3_isolation(self):
        source = Path(__file__).resolve().parents[1]
        source_listing = subprocess.check_output(
            ["git", "-C", str(source), "ls-files", "-z", "--cached", "--others", "--exclude-standard"], timeout=30,
        ).decode().split("\0")
        for relative in sorted(set(source_listing) - {""}):
            original = source / relative
            if not original.is_file() or original.is_symlink():
                continue
            destination = self.repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, destination)
        baseline = self.commit("snapshot the real repository")
        sha2 = self.repo / "algorithms/hash/sha2/sha256/implementations/abc-rust-portable/src/lib.rs"
        self.write(sha2.relative_to(self.repo), sha2.read_text(encoding="utf-8") + "\n// Isolation fixture.\n")
        head = self.commit("change the SHA-256 leaf")
        plan = create_plan(self.repo, baseline, head)
        self.assertFalse(plan["fallback_reason"])
        self.assertTrue({"sha256:rust-tests", "hmac-sha256:test", "hkdf-sha256:test"} <= set(plan["selected_tasks"]))
        self.assertNotIn("sha3-256:test", plan["selected_tasks"])
        gate_plan = ci_plan(self.repo, baseline, head)
        for task in ("repository-assurance:registry", "repository-assurance:status"):
            self.assertEqual(gate_plan["reason_paths"][task], [{"type": "always_required"}])

        sha3 = self.repo / "algorithms/hash/sha3/sha3-256/implementations/abc-rust-portable/src/lib.rs"
        self.write(sha3.relative_to(self.repo), sha3.read_text(encoding="utf-8") + "\n// Isolation fixture.\n")
        end = self.commit("change the SHA3-256 leaf")
        plan = create_plan(self.repo, head, end)
        self.assertFalse(plan["fallback_reason"])
        self.assertIn("sha3-256:test", plan["selected_tasks"])
        self.assertNotIn("sha256:rust-tests", plan["selected_tasks"])

        encoding = self.repo / "foundation/lean/Abc/Foundation/Encoding.lean"
        self.write(encoding.relative_to(self.repo), encoding.read_text(encoding="utf-8") + "\n-- Isolation fixture.\n")
        foundation = self.commit("change the shared Lean encoding")
        plan = create_plan(self.repo, end, foundation)
        self.assertFalse(plan["fallback_reason"])
        self.assertTrue({"lean-encoding-foundation:check", "sha256-spec:check", "sha3-encoding-spec:check"}
                        <= set(plan["selected_tasks"]))
        for task in ("sha256-spec:check", "sha3-encoding-spec:check"):
            self.assertEqual(plan["reason_paths"][task][-1]["type"], "imports")

    def test_ci_cli_plans_runs_and_rejects_incomplete_receipts(self):
        approved = Path(__file__).resolve().parents[1]
        for name in (*VERIFIER_INPUTS, BASELINE_ENTRY):
            self.write(name, (approved / name).read_text(encoding="utf-8"))
        self.write("module.toml", """schema_version = 1
id = "repository-assurance"
owned_paths = ["check.py", "security", "tools"]

[tasks.registry]
kind = "metadata"
always = true
command = ["python", "check.py"]

[tasks.status]
kind = "docs"
always = true
command = ["python", "check.py"]
""")
        self.write("check.py", "assert 1 + 1 == 2\n")
        self.write("runtime/module.toml", """schema_version = 1
id = "runtime"
owned_paths = ["runtime"]

[tasks.check]
kind = "test"
command = ["python", "runtime/check.py"]
""")
        self.write("runtime/check.py", "assert 1 + 1 == 2\n")
        base = self.commit("approved baseline")
        self.write("runtime/check.py", "assert 2 + 2 == 4\n")
        head = self.commit("candidate runtime change")
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        work = Path(directory.name)
        output = work / "matrix.txt"

        def ci(mode, *args, check=True):
            result = subprocess.run(
                [sys.executable, "-B", "-m", "tools.abc_ci", mode, "--repo", str(self.repo), "--base", base,
                 "--head", head, *map(str, args)],
                cwd=approved, env={**os.environ, "GITHUB_OUTPUT": str(output)}, text=True, capture_output=True,
                timeout=30, check=False,
            )
            if check:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result

        ci("plan")
        matrix = json.loads(output.read_text(encoding="utf-8").removeprefix("matrix="))["include"]
        self.assertEqual({row["target"] for row in matrix},
                         {"runtime:check", "repository-assurance:registry", "repository-assurance:status"})
        artifacts = work / "artifacts"
        artifacts.mkdir()
        receipts = []
        for index, row in enumerate(matrix):
            receipt = artifacts / f"abc-task-{row['artifact']}"
            worker_result = work / "workers" / str(index) / "run"
            ci("worker", "--target", row["target"], "--directory", worker_result)
            worker_result.rename(receipt)
            receipts.append(receipt)
        self.assertEqual(json.loads(ci("gate", "--directory", artifacts).stdout)["matrix_jobs"], 3)
        receipts[0].rename(work / "omitted")
        missing = ci("gate", "--directory", artifacts, check=False)
        self.assertEqual(missing.returncode, 1)
        self.assertIn("Incomplete or unexpected set of CI task artifacts", missing.stderr)

        original = (self.repo / BASELINE_ENTRY).read_text(encoding="utf-8")
        self.write(BASELINE_ENTRY, original + "\n# This candidate changes its own verifier.\n")
        head = self.commit("modify the protected baseline entry")
        changed_baseline = ci("plan", check=False)
        self.assertEqual(changed_baseline.returncode, 1)
        self.assertIn(f"Independent review required for assurance changes: {BASELINE_ENTRY}", changed_baseline.stderr)


if __name__ == "__main__":
    unittest.main()
