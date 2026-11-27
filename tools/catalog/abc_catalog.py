"""Review a bounded catalog source snapshot and propose per-subject work."""

from argparse import ArgumentParser
from collections import Counter
from datetime import date
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

from tools.catalog.abc_registry import parse_json, validate, validate_records

REPO = Path(__file__).resolve().parents[2]
DEFAULT_SNAPSHOT = REPO / "docs" / "catalog" / "snapshots" / "seed-2026-11-28.json"
_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_SUBJECT_TYPES = {"algorithm", "construction", "protocol"}
_SOURCE_TYPES = {"standard", "literature"}


def _read_snapshot(payload):
    snapshot = parse_json(payload)
    fields = {"schema_version", "id", "acquired_on", "description", "subjects", "candidate_records"}
    if not isinstance(snapshot, dict) or snapshot.keys() != fields:
        raise ValueError("Expected a closed catalog snapshot object")
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
        raise ValueError("Unsupported catalog snapshot version")
    if not isinstance(snapshot["id"], str) or not _ID.fullmatch(snapshot["id"]):
        raise ValueError("Invalid catalog snapshot identifier")
    if not isinstance(snapshot["description"], str) or not snapshot["description"].strip():
        raise ValueError("Catalog snapshot description is required")
    acquired = snapshot["acquired_on"]
    if not isinstance(acquired, str) or date.fromisoformat(acquired).isoformat() != acquired:
        raise ValueError("Catalog snapshot date must be YYYY-MM-DD")
    if not isinstance(snapshot["subjects"], list) or not snapshot["subjects"]:
        raise ValueError("Catalog snapshot must declare subjects")
    if not isinstance(snapshot["candidate_records"], list):
        raise ValueError("Catalog candidates must be a list")
    return snapshot


def _candidate_overlay(current, candidates):
    proposed = dict(current)
    used = set()
    changes = {"additions": [], "identical": [], "updates_for_review": []}
    for candidate in candidates:
        if not isinstance(candidate, dict) or not isinstance(candidate.get("id"), str):
            raise ValueError("Each catalog candidate needs a registry ID")
        identifier = candidate["id"]
        if identifier in used:
            raise ValueError(f"Duplicate catalog candidate {identifier!r}")
        used.add(identifier)
        registered = current.get(identifier)
        if registered is None:
            changes["additions"].append(candidate)
        elif registered == candidate:
            changes["identical"].append(identifier)
        else:
            changes["updates_for_review"].append({"id": identifier, "current": registered, "proposed": candidate})
        proposed[identifier] = candidate
    return proposed, changes


def _subject_status(snapshot_subjects, current, proposed):
    coverage = Counter()
    indexed = Counter()
    tasks = []
    seen = set()
    for subject in snapshot_subjects:
        if not isinstance(subject, dict) or subject.keys() != {"subject_ref", "workstream", "source_refs"}:
            raise ValueError("Each snapshot subject must name a workstream and publication references")
        identifier = subject["subject_ref"]
        workstream = subject["workstream"]
        sources = subject["source_refs"]
        if not isinstance(identifier, str) or identifier in seen:
            raise ValueError(f"Invalid or duplicate snapshot subject {identifier!r}")
        if not isinstance(workstream, str) or not _ID.fullmatch(workstream):
            raise ValueError(f"Invalid source workstream for {identifier!r}")
        if not isinstance(sources, list) or not sources or any(not isinstance(item, str) for item in sources):
            raise ValueError(f"Source references are required for {identifier!r}")
        if len(set(sources)) != len(sources) or any(proposed.get(ref, {}).get("record_type") not in _SOURCE_TYPES for ref in sources):
            raise ValueError(f"Duplicate or unresolved publication reference for {identifier!r}")
        record = proposed.get(identifier, {})
        if record.get("record_type") not in _SUBJECT_TYPES:
            raise ValueError(f"Snapshot subject {identifier!r} has no canonical or proposed record")
        linked_sources = set(record["standard_refs"]) | set(record["literature_refs"])
        if not set(sources).issubset(linked_sources):
            raise ValueError(f"Snapshot references do not match the subject bibliography for {identifier!r}")
        seen.add(identifier)
        coverage[workstream] += 1
        present = identifier in current
        indexed[workstream] += present
        registered = current.get(identifier, {})
        actions = []
        if registered != record:
            actions.append("Review the proposed identity, sources, and parameter relationships.")
        if not registered.get("spec_refs"):
            actions.append("Define the independent specification and applicable input domain.")
        if not any(candidate.get("record_type") == "implementation" and candidate.get("subject_ref") == identifier
                   and candidate.get("maintenance", {}).get("state") != "catalog-only" for candidate in current.values()):
            actions.append("Identify a rights-cleared implementation and track target-specific verification.")
        if not actions:
            actions.append("Check proof and testing coverage for the selected implementation.")
        tasks.append({
            "id": f"catalog-{identifier.removeprefix('abc:').replace(':', '-')}",
            "subject_ref": identifier,
            "workstream": workstream,
            "source_refs": sources,
            "status": "queued",
            "actions": actions,
        })
    return {
        "source_subjects": sum(coverage.values()),
        "indexed_subjects": sum(indexed.values()),
        "workstreams": {
            name: {"indexed": indexed[name], "source_subjects": count}
            for name, count in sorted(coverage.items())
        },
    }, tasks


def review(repo, payload):
    """Validate current plus proposed records without writing canonical metadata."""
    snapshot = _read_snapshot(payload)
    current = {record["id"]: record for record in validate(repo)["records"]}
    proposed, changes = _candidate_overlay(current, snapshot["candidate_records"])
    validate_records(repo, [(record_id, record) for record_id, record in sorted(proposed.items())])
    coverage, tasks = _subject_status(snapshot["subjects"], current, proposed)
    return {
        "schema_version": 1,
        "snapshot": {
            "id": snapshot["id"],
            "acquired_on": snapshot["acquired_on"],
            "description": snapshot["description"],
            "sha256": sha256(payload).hexdigest(),
        },
        "coverage": coverage,
        "changes": changes,
        "tasks": tasks,
    }


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    arguments = parser.parse_args()
    try:
        result = review(REPO, arguments.snapshot.read_bytes())
    except (OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
