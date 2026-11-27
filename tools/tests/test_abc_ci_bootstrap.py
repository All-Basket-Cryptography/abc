"""Exercise both sides of initial CI trust establishment in committed fixtures."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.verification.abc_ci import BASELINE_ENTRY


APPROVED = Path(__file__).resolve().parents[2]


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.repo = Path(directory.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "core.autocrlf", "false")
        self.write("README.md", "ABC initial review seed.\n")
        self.base = self.commit("seed the default branch")
        self.write("tools/abc_cli.py", """import sys
assert sys.argv[1:] == ['registry', 'validate', '--strict']
print('registry fixture accepted')
""")
        self.write("tools/tests/fixtures/registry/test_contract.py", """import unittest

class Contract(unittest.TestCase):
    def test_case(self):
        self.assertEqual(len({'registry': 'valid'}), 1)
""")
        self.write("tools/tests/test_runtime.py", """import unittest

class Runtime(unittest.TestCase):
    def test_case(self):
        self.assertEqual(bytes.fromhex('616263'), b'abc')
""")
        self.write(BASELINE_ENTRY, (APPROVED / BASELINE_ENTRY).read_text(encoding="utf-8"))
        self.head = self.commit("candidate check tools and fixtures")

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), "-c", "user.name=ABC fixture",
             "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
             "-c", "core.hooksPath=.unused-fixture-hooks", *args], text=True, timeout=30,
        ).strip()

    def write(self, relative, contents):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8", newline="\n")

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def ci(self, mode, *, base=None, head=None):
        return subprocess.run(
            [sys.executable, "-B", "-m", "tools.verification.abc_ci", mode, "--repo", str(self.repo), "--base",
             base or self.base, "--head", head or self.head],
            cwd=APPROVED, capture_output=True, text=True, timeout=30, check=False,
        )

    def test_candidate_fixtures_are_advisory_until_a_baseline_exists(self):
        advisory = self.ci("bootstrap")
        self.assertEqual(advisory.returncode, 0, advisory.stderr)
        self.assertIn("registry fixture accepted", advisory.stdout)
        self.assertEqual(advisory.stderr.count("Ran 1 test"), 2)
        self.assertEqual(json.loads(advisory.stdout.splitlines()[-1]), {
            "status": "advisory-passed", "domain": "untrusted-pr", "head_revision": self.head,
            "review": "independent-review-required",
        })
        for mode in ("plan", "gate"):
            blocked = self.ci(mode)
            self.assertEqual(blocked.returncode, 1)
            self.assertIn("reviewed CI baseline is absent", blocked.stderr)

    def test_failing_fixture_stops_the_advisory(self):
        self.write("tools/tests/test_runtime.py", (self.repo / "tools/tests/test_runtime.py").read_text(encoding="utf-8")
                   .replace("b'abc'", "b'def'"))
        broken = self.commit("mutate the candidate fixture")
        result = self.ci("bootstrap", head=broken)
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL: test_case", result.stderr)
        self.assertNotIn("advisory-passed", result.stdout)

    def test_bootstrap_cannot_replace_existing_baseline_verification(self):
        self.write("README.md", "ABC review seed documentation change.\n")
        next_head = self.commit("normal candidate documentation")
        result = self.ci("bootstrap", base=self.head, head=next_head)
        self.assertEqual(result.returncode, 1)
        self.assertIn("reviewed CI baseline exists", result.stderr)


if __name__ == "__main__":
    unittest.main()
