"""Exercise actual processes, authentication, and final receipt checking."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.abc_ci import gate
from tools.abc_graph import create_plan
from tools.abc_runner import _digest, execute, verify_receipt


MANIFEST = """schema_version = 1
id = "sample"
owned_paths = ["sample.py"]

[tasks.alpha]
command = ["python", "sample.py"]
timeout_seconds = 5

[tasks.consumer]
command = ["python", "sample.py", "consumer"]
dependencies = ["alpha"]
outputs = ["test.txt"]
timeout_seconds = 5
"""

SCRIPT = """from pathlib import Path
import os
import sys
if 'consumer' in sys.argv:
    Path(os.environ['ABC_TASK_OUTPUT'], 'test.txt').write_text('ready', encoding='utf-8')
print('fixture ran')
"""


class RunnerTest(unittest.TestCase):
    def setUp(self):
        location = tempfile.TemporaryDirectory()
        self.addCleanup(location.cleanup)
        self.root = Path(location.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        (self.repo / "tools").mkdir()
        (self.repo / "security").mkdir()
        for path in ("abc.py", "tools/abc_graph.py", "tools/abc_runner.py", "security/assurance-policy.json"):
            (self.repo / path).write_text("fixture verifier\n", encoding="utf-8")
        (self.repo / "module.toml").write_text(MANIFEST, encoding="utf-8")
        (self.repo / "sample.py").write_text(SCRIPT, encoding="utf-8")
        self.plan_path = self.root / "plan.json"
        self.plan = self.make_plan()
        self.key = self.root / "test-key"
        self.key.write_bytes(bytes(range(32)))

    def make_plan(self):
        plan = create_plan(self.repo)
        self.plan_path.write_text(json.dumps(plan), encoding="utf-8")
        return plan

    def test_local_authentication_cache_and_tamper(self):
        cache = self.root / "cache"
        first = self.root / "run1"
        second = self.root / "run2"
        self.assertEqual(execute(self.repo, self.plan_path, first, "local", self.key, cache)["status"], "passed")
        self.assertEqual(verify_receipt(self.repo, self.plan_path, first, "local", self.key)["task_count"], 2)
        reused = execute(self.repo, self.plan_path, second, "local", self.key, cache)["results"]
        self.assertTrue(reused["sample:alpha"]["cached"])
        self.assertFalse(reused["sample:consumer"]["cached"])
        self.assertEqual(verify_receipt(self.repo, self.plan_path, second, "local", self.key)["status"], "verified")
        with self.assertRaisesRegex(ValueError, "Only independently keyed local"):
            verify_receipt(self.repo, self.plan_path, first, "release", self.key)
        target = second / "tasks" / _digest("sample:consumer") / "artifacts/test.txt"
        target.write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Invalid evidence"):
            verify_receipt(self.repo, self.plan_path, second, "local", self.key)
        receipt_path = first / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["payload"]["results"].pop("sample:alpha")
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "authentication failed"):
            verify_receipt(self.repo, self.plan_path, first, "local", self.key)

    def test_stale_and_modified_plan_is_refused(self):
        first = self.root / "run1"
        execute(self.repo, self.plan_path, first, "local", self.key)
        (self.repo / "sample.py").write_text(SCRIPT + "\n# changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            verify_receipt(self.repo, self.plan_path, first, "local", self.key)
        self.make_plan()
        with self.assertRaisesRegex(ValueError, "stale"):
            verify_receipt(self.repo, self.plan_path, first, "local", self.key)
        self.plan_path.write_text(json.dumps({**self.plan, "selected_tasks": []}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            execute(self.repo, self.plan_path, self.root / "run2", "local")

    def test_gate_rejects_failed_tasks_and_missing_artifacts(self):
        downloaded = self.root / "downloaded"
        for name in self.plan["selected_tasks"]:
            directory = downloaded / f"abc-task-{_digest(name)}"
            execute(self.repo, self.plan_path, directory, "untrusted-pr", target=name)
        self.assertEqual(gate(self.plan, downloaded)["matrix_jobs"], 2)
        victim = downloaded / f"abc-task-{_digest('sample:alpha')}"
        shutil.move(victim, self.root / "missing")
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            gate(self.plan, downloaded)
        (self.repo / "sample.py").write_text("raise SystemExit(3)\n", encoding="utf-8")
        self.make_plan()
        failed = execute(self.repo, self.plan_path, self.root / "failed", "local")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["results"]["sample:alpha"]["status"], "failed")
        self.assertEqual(failed["results"]["sample:consumer"]["status"], "not_run")

    def test_timeout_skips_dependents(self):
        (self.repo / "module.toml").write_text(MANIFEST.replace("timeout_seconds = 5", "timeout_seconds = 1"), encoding="utf-8")
        (self.repo / "sample.py").write_text("from time import sleep\nsleep(10)\n", encoding="utf-8")
        self.make_plan()
        failed = execute(self.repo, self.plan_path, self.root / "timeout", "local")
        self.assertEqual(failed["results"]["sample:alpha"]["status"], "timeout")
        self.assertEqual(failed["results"]["sample:consumer"]["status"], "not_run")
