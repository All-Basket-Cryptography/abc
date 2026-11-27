from copy import deepcopy
from pathlib import Path
import tomllib
import unittest

from tools.abc_registry import (
    RegistryValidationError,
    parse_json,
    validate,
    validate_module_shape,
    validate_records,
)


FIXTURES = Path(__file__).resolve().parent
REPO = FIXTURES.parents[1]


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = validate(REPO)["records"]
        cls.fixtures = parse_json((FIXTURES / "positive.json").read_text(encoding="utf-8"))

    def validate_fixture(self, fixtures):
        records = [*self.catalog, *fixtures]
        return validate_records(REPO, [(f"record {index}", record) for index, record in enumerate(records)])

    def test_catalog_and_contracts(self):
        result = self.validate_fixture(self.fixtures)
        self.assertEqual(result["record_count"], len(self.catalog) + len(self.fixtures))
        lifecycle = {record.get("lifecycle") for record in self.catalog}
        self.assertTrue({"historical", "broken", "standardized", "experimental"} <= lifecycle)
        catalog_evidence_count = sum(record["record_type"] == "evidence-result" for record in self.catalog)
        self.assertEqual(result["counts"]["evidence-result"], catalog_evidence_count + 1)

    def test_rejects_invalid_records(self):
        cases = [
            (0, "schema_version", "1", "expected 1"),
            (0, "schema_version", True, "expected 1"),
            (0, "verified", True, "unknown field"),
            (0, "subject_ref", "abc:algorithm:absent", "unresolved reference"),
            (0, "subject_ref", "abc:parameter:secp256k1", "required format"),
            (1, "path", "../file", "unsafe"),
            (1, "path", "registry/NUL.json", "unsafe"),
            (1, "path", "C:/file", "required format"),
            (1, "path", "registry\\file", "required format"),
            (1, "id", self.fixtures[0]["id"], "required format"),
            (1, "origin", "upstream", "pinned source digest"),
            (4, "theorems", [], "must name the required theorems"),
            (5, "state", "proved", "recorded execution"),
            (5, "state", "passed", "invalid state"),
            (5, "state", "not_applicable", "reason and reviewer"),
            (7, "support_until", "2026-02-31", "invalid calendar date"),
            (7, "approval", "approved", "requires review"),
            (8, "alias_id", "abc:algorithm:sha-256", "identifier already in use"),
        ]
        for index, field, value, expected in cases:
            with self.subTest(index=index, field=field, value=value):
                records = deepcopy(self.fixtures)
                records[index][field] = value
                with self.assertRaisesRegex(RegistryValidationError, expected):
                    self.validate_fixture(records)

    def test_rejects_duplicate_identifiers(self):
        with self.assertRaisesRegex(RegistryValidationError, "duplicate identifier"):
            self.validate_fixture([*self.fixtures, self.fixtures[1]])

    def test_rejects_duplicate_keys_and_tagged_yaml(self):
        for name, expected in [
            ("duplicate-key.json", "duplicate JSON key"),
            ("tagged.yaml", "Expecting value"),
        ]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, expected):
                parse_json((FIXTURES / name).read_text(encoding="utf-8"))

    def test_module_contract(self):
        manifest = tomllib.loads((FIXTURES / "positive-module.toml").read_text(encoding="utf-8"))
        validate_module_shape(REPO, manifest)
        manifest["tasks"]["check"]["command"] = "python -m unittest"
        with self.assertRaisesRegex(RegistryValidationError, "expected array"):
            validate_module_shape(REPO, manifest)


if __name__ == "__main__":
    unittest.main()
