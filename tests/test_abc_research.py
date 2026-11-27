"""Exercise detached approval and checkpoint recovery with real task receipts."""

import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools.abc_graph import create_plan
from tools.abc_research import NAMESPACE, propose, resume
from tools.abc_runner import _digest, verify_receipt


MANIFEST = """schema_version = 1
id = "sample"
owned_paths = ["sample.py"]

[tasks.first]
command = ["python", "sample.py"]
timeout_seconds = 5

[tasks.second]
command = ["python", "sample.py", "second"]
dependencies = ["first"]
outputs = ["output.txt"]
timeout_seconds = 5
"""
SCRIPT = """from pathlib import Path
import os
import sys
print('actual task subprocess')
if 'second' in sys.argv:
    if not (Path(__file__).resolve().parents[1] / 'resource-ready').exists():
        raise SystemExit(3)
    Path(os.environ['ABC_TASK_OUTPUT'], 'output.txt').write_text('checked', encoding='utf-8')
"""


@unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH is required for checkpoint signature tests")
class ResearchCheckpointTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.directory = self.root / "checkpoint"
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        (self.repo / "tools").mkdir()
        (self.repo / "security").mkdir()
        for path in ("tools/abc_cli.py", "tools/abc_graph.py", "tools/abc_runner.py", "security/assurance-policy.json"):
            (self.repo / path).write_text("fixture execution policy\n", encoding="utf-8")
        (self.repo / "module.toml").write_text(MANIFEST, encoding="utf-8")
        self.script = self.repo / "sample.py"
        self.script.write_text(SCRIPT, encoding="utf-8")

        self.signing_key = self.root / "fixture-signing-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.signing_key)],
            check=True, capture_output=True,
        )
        self.signers = self.root / "allowed_signers"
        self.signers.write_text(
            "fixture-reviewer " + self.signing_key.with_suffix(".pub").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self.key = self.root / "fixture-receipt-key"
        self.key.write_bytes(bytes(range(32)))
        self.signature = self.directory / "proposal.json.sig"

    def make_proposal(self, max_attempts=2, budget_seconds=20):
        return propose(
            self.repo, self.directory, target="sample:second", max_attempts=max_attempts,
            budget_seconds=budget_seconds,
        )

    def sign(self):
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.signing_key), "-n", NAMESPACE,
             str(self.directory / "proposal.json")],
            check=True, capture_output=True,
        )

    def resume(self, reviewer="fixture-reviewer"):
        return resume(
            self.repo, self.directory, signature=self.signature, signers=self.signers,
            reviewer=reviewer, key_file=self.key,
        )

    def test_real_retry_cache_and_idempotent_resume(self):
        self.make_proposal()
        self.assertFalse(self.signature.exists())
        self.sign()
        first = self.resume()
        self.assertEqual(first["status"], "failed")
        self.assertEqual(first["attempts"][0]["task_statuses"], {"sample:first": "passed", "sample:second": "failed"})
        (self.root / "resource-ready").touch()
        second = self.resume()
        self.assertEqual(second["status"], "passed")
        self.assertEqual(second["attempts"][1]["cached_tasks"], ["sample:first"])
        self.assertIsNotNone(second["attempts"][1]["receipt"])
        self.assertEqual(len(self.resume()["attempts"]), 2)

        run = self.directory / "attempt-0002"
        plan = self.directory / "plan.json"
        self.assertEqual(verify_receipt(self.repo, plan, run, "local", self.key, target="sample:second")["status"], "verified")
        with self.assertRaisesRegex(ValueError, "trust scope"):
            verify_receipt(self.repo, plan, run, "local", self.key)
        artifact = run / "tasks" / _digest("sample:second") / "artifacts/output.txt"
        artifact.write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Invalid evidence"):
            self.resume()

    def test_stale_approved_proposal_and_replaced_plan_fail(self):
        self.make_proposal()
        self.sign()
        self.assertEqual(self.resume()["status"], "failed")
        self.assertTrue((self.directory / "checkpoint.json").is_file())
        self.script.write_text(SCRIPT + "\n# source changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "no longer matches"):
            self.resume()
        plan = self.directory / "plan.json"
        plan.write_text(json.dumps(create_plan(self.repo)), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            self.resume()
        self.assertFalse((self.directory / "attempt-0002").exists())

    def test_independent_signature_and_resource_limits(self):
        with self.assertRaisesRegex(ValueError, "requires at least 20"):
            self.make_proposal(budget_seconds=19)
        self.make_proposal(max_attempts=1, budget_seconds=10)
        self.sign()
        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            self.resume(reviewer="unapproved-reviewer")
        self.assertEqual(self.resume()["status"], "failed")
        exhausted = self.resume()
        self.assertEqual(exhausted["status"], "budget_exhausted")
        self.assertEqual(len(exhausted["attempts"]), 1)

    def test_interrupted_attempt_consumes_its_reservation(self):
        self.make_proposal()
        self.sign()
        with patch("tools.abc_research.execute", side_effect=OSError("fixture interruption before execution")):
            with self.assertRaisesRegex(OSError, "fixture interruption"):
                self.resume()
        (self.root / "resource-ready").touch()
        recovered = self.resume()
        self.assertEqual([attempt["status"] for attempt in recovered["attempts"]], ["interrupted", "passed"])
        self.assertIsNone(recovered["attempts"][0]["receipt"])


if __name__ == "__main__":
    unittest.main()
