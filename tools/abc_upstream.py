"""Inventory pinned sources and match registered consumers to advisory scope."""

from argparse import ArgumentParser
from copy import deepcopy
import json
from pathlib import Path
import sys

from tools.abc_registry import parse_json, validate, validate_records


REPO = Path(__file__).resolve().parents[1]


def inventory(records):
    """Export comparable upstream and advisory snapshots."""
    upstream = [record for record in records if record["record_type"] == "implementation" and record["origin"] == "upstream"]
    advisories = [record for record in records if record["record_type"] == "advisory"]
    return {
        "schema_version": 1,
        "implementations": {record["id"]: record for record in upstream},
        "advisories": {record["id"]: record for record in advisories},
    }


def compare_inventory(previous, current):
    """Report catalog additions, removals, and changes by stable record ID."""
    if not isinstance(previous, dict) or previous.get("schema_version") != 1:
        raise ValueError("Expected an upstream inventory version 1")
    changes = {}
    for section in ("implementations", "advisories"):
        old = previous.get(section)
        new = current[section]
        if not isinstance(old, dict):
            raise ValueError(f"Inventory is missing object {section!r}")
        changes[section] = {
            "added": sorted(new.keys() - old.keys()),
            "removed": sorted(old.keys() - new.keys()),
            "changed": sorted(key for key in old.keys() & new.keys() if old[key] != new[key]),
        }
    return changes


def affected_releases(records, implementation_id, *, revision=None, target=None, features=(), advisory_id=None):
    """Match exact recorded snapshots, with a separate follow-up queue for missing metadata."""
    by_id = {record["id"]: record for record in records}
    implementation = by_id.get(implementation_id)
    if not implementation or implementation["record_type"] != "implementation":
        raise ValueError(f"Unknown implementation {implementation_id!r}")
    if target is not None and by_id.get(target, {}).get("record_type") != "build-target":
        raise ValueError(f"Unknown build target {target!r}")

    revisions = set()
    targets = set()
    required_features = set(features)
    if advisory_id is not None:
        advisory = by_id.get(advisory_id)
        if not advisory or advisory["record_type"] != "advisory":
            raise ValueError(f"Unknown advisory {advisory_id!r}")
        if advisory["disclosure"] != "public" or implementation_id not in advisory["implementation_refs"]:
            raise ValueError("Advisory must be public and reference the selected implementation")
        revisions.update(advisory["affected_versions"])
        targets.update(advisory["target_refs"])
        required_features.update(advisory["features"])
    if revision is not None:
        if revisions and revision not in revisions:
            raise ValueError("Requested revision is outside the advisory scope")
        revisions = {revision}
    if target is not None:
        if targets and target not in targets:
            raise ValueError("Requested target is outside the advisory scope")
        targets = {target}

    exact = []
    review = []
    for release in records:
        if release["record_type"] != "release-set":
            continue
        for package in release["packages"]:
            binding = by_id[package["binding_ref"]]
            if binding["implementation_ref"] != implementation_id:
                continue
            captured_revision = package.get("implementation_revision")
            captured_target = package.get("build_target_ref")
            captured_features = package.get("features")
            if captured_revision is not None and revisions and captured_revision not in revisions:
                continue
            if captured_target is not None and targets and captured_target not in targets:
                continue
            if captured_target is None and targets and not targets.intersection(binding["target_refs"]):
                continue
            if captured_features is not None and not required_features.issubset(captured_features):
                continue

            missing = []
            if revisions and captured_revision is None:
                missing.append("implementation_revision")
            if targets and captured_target is None:
                missing.append("build_target_ref")
            if required_features and captured_features is None:
                missing.append("features")
            match = {
                "release_ref": release["id"],
                "package": package["package_name"],
                "package_version": package["version"],
                "ecosystem": package["ecosystem"],
                "binding_ref": binding["id"],
                "implementation_revision": captured_revision,
                "build_target_ref": captured_target,
                "features": captured_features,
            }
            if missing:
                review.append({**match, "missing_scope": missing})
            else:
                exact.append(match)
    return {
        "implementation_ref": implementation_id,
        "advisory_ref": advisory_id,
        "matching_scope": {
            "revisions": sorted(revisions),
            "targets": sorted(targets),
            "required_features": sorted(required_features),
        },
        "affected": exact,
        "needs_review": review,
    }


def drill(repo, records, wheel=None):
    """Exercise snapshot matching using an in-memory fictional upstream issue."""
    fixture_path = "fixtures/registry/positive.json"
    fixtures = parse_json((repo / fixture_path).read_text(encoding="utf-8"))
    by_type = {record["record_type"]: record for record in fixtures}
    implementation = by_type["implementation"]
    implementation.update(origin="upstream", revision="2.0.0", source_sha256="1" * 64, features=["optimized", "portable"])
    binding = by_type["binding"]
    old_binding = binding["id"]
    binding.update(id="abc:binding:fixture-python", ecosystem="pypi", language="python", runtime="CPython 3.13")
    policy = by_type["policy"]
    policy["allowed_subject_refs"] = [
        binding["id"] if reference == old_binding else reference for reference in policy["allowed_subject_refs"]
    ]
    target = by_type["build-target"]
    target.update(triple="x86_64-pc-windows-msvc", os="windows", abi="ABC C ABI version 1", runtime="CPython 3.13")
    release = by_type["release-set"]
    release["name"] = "Synthetic affected release"
    package = release["packages"][0]
    package.update(
        binding_ref=binding["id"], ecosystem=binding["ecosystem"], implementation_revision="1.4.0",
        build_target_ref=target["id"], features=["optimized"],
    )
    retained = deepcopy(release)
    retained.update(id="abc:release-set:fixture-retained", name="Synthetic backported release")
    retained["packages"][0].update(version="0.0.1", features=["portable"])
    migrated = deepcopy(release)
    migrated.update(id="abc:release-set:fixture-migrated", name="Synthetic migrated release")
    migrated["packages"][0].update(version="0.1.0", implementation_revision="2.0.0")
    unverified = deepcopy(release)
    unverified.update(id="abc:release-set:fixture-unverified", name="Synthetic incomplete historic release")
    del unverified["packages"][0]["implementation_revision"]
    advisory = {
        "schema_version": 1, "id": "abc:advisory:fixture-upstream-drill",
        "record_type": "advisory", "name": "Synthetic upstream maintenance issue",
        "sources": [{"path": fixture_path, "locator": "Fictional drill subjects."}],
        "owner": {"state": "unassigned", "contacts": []},
        "implementation_refs": [implementation["id"]],
        "affected_versions": ["1.4.0"],
        "features": ["optimized"],
        "target_refs": [target["id"]],
        "use_cases": ["Exercise the affected-release query."],
        "risk": "Fictional upstream discontinuity with a feature-specific affected branch.",
        "mitigation": "Use the compatible portable backport or migrate to the replacement revision.",
        "evidence_result_refs": [], "disclosure": "public", "external_ids": [],
    }
    study = [*fixtures, retained, migrated, unverified, advisory]
    entries = [("registry", record) for record in records] + [(fixture_path, record) for record in study]
    checked = validate_records(repo, entries)["records"]
    result = affected_releases(checked, implementation["id"], advisory_id=advisory["id"])
    if [item["release_ref"] for item in result["affected"]] != [release["id"]]:
        raise ValueError("Synthetic affected-release set differed from the expected exact match")
    if [item["release_ref"] for item in result["needs_review"]] != [unverified["id"]]:
        raise ValueError("Synthetic incomplete release was not flagged for source review")
    result["synthetic"] = True
    result["backport"] = retained["id"]
    result["migration"] = {"release_ref": migrated["id"], "provider_compatibility": "not_run"}
    if wheel is not None:
        from sdk.python.wheel import test_distribution
        test_distribution(wheel)
        result["migration"]["provider_compatibility"] = "passed-installed-abc-python-vs-hashlib"
    return result


def main():
    parser = ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inventory")
    comparison = commands.add_parser("compare")
    comparison.add_argument("--previous", required=True, type=Path)
    affected = commands.add_parser("affected")
    affected.add_argument("--implementation", required=True)
    affected.add_argument("--revision")
    affected.add_argument("--target")
    affected.add_argument("--feature", action="append", default=[])
    affected.add_argument("--advisory")
    rehearsal = commands.add_parser("drill")
    rehearsal.add_argument("--wheel", type=Path)
    arguments = parser.parse_args()
    try:
        records = validate(REPO)["records"]
        if arguments.command == "inventory":
            result = inventory(records)
        elif arguments.command == "compare":
            previous = parse_json(arguments.previous.read_text(encoding="utf-8"))
            result = compare_inventory(previous, inventory(records))
        elif arguments.command == "affected":
            result = affected_releases(
                records, arguments.implementation, revision=arguments.revision, target=arguments.target,
                features=arguments.feature, advisory_id=arguments.advisory,
            )
        else:
            result = drill(REPO, records, arguments.wheel)
    except (OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
