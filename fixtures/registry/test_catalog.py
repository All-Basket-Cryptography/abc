"""Regression cases for archive review without registry writes."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import unittest

from tools.abc_catalog import DEFAULT_SNAPSHOT, review
from tools.abc_registry import parse_json


REPO = Path(__file__).resolve().parents[2]


class CatalogReviewTests(unittest.TestCase):
    def test_bounded_coverage_and_tasks(self):
        payload = DEFAULT_SNAPSHOT.read_bytes()
        result = review(REPO, payload)
        self.assertEqual(result["snapshot"]["sha256"], sha256(payload).hexdigest())
        self.assertEqual(result["coverage"]["source_subjects"], 8)
        self.assertEqual(result["coverage"]["indexed_subjects"], 8)
        self.assertEqual(
            set(result["coverage"]["workstreams"]),
            {"classical", "fhe", "mainstream", "mpc", "pqc", "zero-knowledge"},
        )
        self.assertEqual(len(result["tasks"]), 8)
        self.assertTrue(all(task["source_refs"] and task["actions"] for task in result["tasks"]))
        self.assertGreater(len(result["changes"]["identical"]), 0)

    def test_proposals_preserve_current_values(self):
        snapshot = parse_json(DEFAULT_SNAPSHOT.read_bytes())
        original = next(record for record in snapshot["candidate_records"] if record["record_type"] == "alias")
        new = deepcopy(original)
        new.update(id="abc:alias:sha256-review-example", alias_id="abc:algorithm:sha256-review-example")
        snapshot["candidate_records"].append(new)
        original["name"] = "Proposed review title"
        result = review(REPO, json.dumps(snapshot).encode())
        self.assertIn(new, result["changes"]["additions"])
        updates = result["changes"]["updates_for_review"]
        change = next(update for update in updates if update["id"] == original["id"])
        self.assertNotEqual(change["current"]["name"], change["proposed"]["name"])
        self.assertEqual(change["proposed"]["name"], original["name"])

    def test_rejects_duplicate_and_unresolved_sources(self):
        snapshot = parse_json(DEFAULT_SNAPSHOT.read_bytes())
        snapshot["candidate_records"].append(snapshot["candidate_records"][0])
        with self.assertRaisesRegex(ValueError, "Duplicate catalog candidate"):
            review(REPO, json.dumps(snapshot).encode())

        snapshot["candidate_records"].pop()
        snapshot["subjects"][0]["source_refs"] = ["abc:standard:nonexistent"]
        with self.assertRaisesRegex(ValueError, "unresolved publication reference"):
            review(REPO, json.dumps(snapshot).encode())


if __name__ == "__main__":
    unittest.main()
