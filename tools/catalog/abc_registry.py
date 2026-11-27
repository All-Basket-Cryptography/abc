"""Validate versioned ABC metadata and its typed references offline."""

from collections import Counter
from datetime import date, datetime
from functools import lru_cache
from json import loads
from pathlib import Path
import re
from urllib.parse import urlsplit


class RegistryValidationError(ValueError):
    def __init__(self, errors):
        self.errors = tuple(errors)
        super().__init__("\n".join(self.errors))


def parse_json(payload):
    """Decode the canonical JSON subset of YAML 1.2 without duplicate keys."""

    def object_from_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError(f"invalid JSON constant {value!r}")

    return loads(
        payload,
        object_pairs_hook=object_from_pairs,
        parse_constant=reject_constant,
    )


def _read_json(path):
    try:
        return parse_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as error:
        raise RegistryValidationError([f"{path}: {error}"]) from error


def _valid_path(value):
    windows_device = r"(?:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³])(?:\..*)?"
    return all(
        not part.endswith((".", " "))
        and not re.fullmatch(windows_device, part, re.IGNORECASE)
        for part in value.split("/")
    )


_SCHEMA_KEYS = {
    "$schema", "$defs", "$ref", "title", "description", "type", "const",
    "enum", "minLength", "pattern", "minimum", "maximum", "minItems",
    "uniqueItems", "items", "properties", "required", "minProperties",
    "additionalProperties", "oneOf",
}
_SCHEMA_TYPES = {"array": list, "boolean": bool, "integer": int, "object": dict, "string": str}


def _resolve_ref(ref, definitions):
    if not re.fullmatch(r"#/\$defs/[a-z][a-z0-9_-]*", ref):
        raise RegistryValidationError([f"only local definitions are supported: {ref}"])
    name = ref.rsplit("/", 1)[1]
    if name not in definitions:
        raise RegistryValidationError([f"missing schema definition {ref}"])
    return name, definitions[name]


def _check_schema(schema, definitions):
    unknown = schema.keys() - _SCHEMA_KEYS
    if unknown:
        raise RegistryValidationError([f"unsupported JSON Schema keywords: {sorted(unknown)}"])
    if "$ref" in schema:
        _resolve_ref(schema["$ref"], definitions)
        if len(schema) != 1:
            raise RegistryValidationError(["schema references cannot have sibling keywords"])
    if "type" in schema and schema["type"] not in _SCHEMA_TYPES:
        raise RegistryValidationError([f"unsupported JSON Schema type: {schema['type']}"])
    for keyword in ("$defs", "properties"):
        for child in schema.get(keyword, {}).values():
            _check_schema(child, definitions)
    for keyword in ("items", "additionalProperties"):
        if isinstance(schema.get(keyword), dict):
            _check_schema(schema[keyword], definitions)
    for child in schema.get("oneOf", ()):
        _check_schema(child, definitions)


@lru_cache(maxsize=8)
def _compile_schema(payload):
    try:
        schema = parse_json(payload)
    except (ValueError, RecursionError) as error:
        raise RegistryValidationError([f"schema: {error}"]) from error
    if not isinstance(schema, dict) or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise RegistryValidationError(["schema must declare JSON Schema Draft 2020-12"])
    _check_schema(schema, schema.get("$defs", {}))
    return schema


def _schema(path):
    try:
        return _compile_schema(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        raise RegistryValidationError([f"{path}: {error}"]) from error


def _location(where, field):
    return f"{where}/{str(field).replace('~', '~0').replace('/', '~1')}"


def _errors(value, rule, where, definitions, refs=()):
    """Evaluate the JSON Schema vocabulary used by the checked-in contracts."""
    if "$ref" in rule:
        name, target = _resolve_ref(rule["$ref"], definitions)
        if name in refs:
            raise RegistryValidationError([f"recursive schema definition {name}"])
        errors = _errors(value, target, where, definitions, (*refs, name))
        if not errors and name == "path" and not _valid_path(value):
            errors.append(f"{where}: unsafe or non-portable repository path")
        if not errors and name == "date":
            try:
                date.fromisoformat(value)
            except ValueError:
                errors.append(f"{where}: invalid calendar date")
        if not errors and name == "url":
            try:
                url = urlsplit(value)
                valid = bool(url.hostname) and not url.username and not url.password
            except ValueError:
                valid = False
            if not valid or "\\" in value:
                errors.append(f"{where}: invalid source URL")
        return errors

    if "oneOf" in rule:
        option_errors = [_errors(value, option, where, definitions, refs) for option in rule["oneOf"]]
        matches = sum(not issues for issues in option_errors)
        if matches == 0:
            return min(option_errors, key=len)
        if matches != 1:
            return [f"{where}: must match exactly one allowed shape"]
    if "type" in rule and type(value) is not _SCHEMA_TYPES[rule["type"]]:
        return [f"{where}: expected {rule['type']}"]
    if "const" in rule:
        expected = rule["const"]
        if type(value) is not type(expected) or value != expected:
            return [f"{where}: expected {expected!r}"]
    if "enum" in rule and value not in rule["enum"]:
        return [f"{where}: expected one of {', '.join(map(str, rule['enum']))}"]

    errors = []
    if isinstance(value, str):
        if len(value) < rule.get("minLength", 0):
            errors.append(f"{where}: value must not be empty")
        if "pattern" in rule and not re.search(rule["pattern"], value):
            errors.append(f"{where}: does not match the required format")
        elif "pattern" in rule and rule["pattern"].endswith("$") and value.endswith("\n"):
            errors.append(f"{where}: unexpected trailing newline")
    elif type(value) is int:
        if value < rule.get("minimum", value) or value > rule.get("maximum", value):
            errors.append(f"{where}: integer is outside the supported range")
    elif isinstance(value, list):
        if len(value) < rule.get("minItems", 0):
            errors.append(f"{where}: too few items")
        if rule.get("uniqueItems") and any(item in value[:index] for index, item in enumerate(value)):
            errors.append(f"{where}: duplicate array element")
        for index, item in enumerate(value):
            errors.extend(_errors(item, rule.get("items", {}), _location(where, index), definitions, refs))
    elif isinstance(value, dict):
        if len(value) < rule.get("minProperties", 0):
            errors.append(f"{where}: too few properties")
        for key in rule.get("required", ()):
            if key not in value:
                errors.append(f"{_location(where, key)}: required field missing")
        properties = rule.get("properties", {})
        additional = rule.get("additionalProperties", {})
        for key, item in value.items():
            child = properties.get(key, additional)
            if child is False:
                errors.append(f"{_location(where, key)}: unknown field")
            elif child is not True:
                errors.extend(_errors(item, child, _location(where, key), definitions, refs))
    return errors


def validate_module_shape(repo: Path, manifest: dict):
    schema = _schema(repo / "registry/schemas" / "module.schema.json")
    errors = _errors(manifest, schema, "module.toml", schema["$defs"])
    if errors:
        raise RegistryValidationError(errors)


def iter_references(value, where=""):
    """Yield (field pointer, record ID) for the registry's reference fields."""
    if isinstance(value, dict):
        for key, item in value.items():
            location = _location(where, key)
            if key.endswith("_ref"):
                yield location, item
            elif key.endswith("_refs"):
                for index, ref in enumerate(item):
                    yield _location(location, index), ref
            else:
                yield from iter_references(item, location)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_references(item, _location(where, index))


_FORMAL_STATES = {"missing", "in_progress", "partial", "proved", "refuted", "blocked", "not_applicable"}
_RUN_STATES = {"not_run", "passed", "failed", "blocked", "not_applicable"}
_OBSERVED_STATES = {"partial", "proved", "refuted", "passed", "failed"}


def _semantic_errors(records, locations):
    errors = []
    inactive = set()
    for record_id, record in records.items():
        location = locations[record_id]

        def report(field, message):
            errors.append(f"{_location(location, field)}: {message}")

        for pointer, target_id in iter_references(record, location):
            if target_id not in records:
                errors.append(f"{pointer}: unresolved reference {target_id!r}")
            elif target_id == record_id:
                errors.append(f"{pointer}: self-reference is not permitted")

        for field in ("owner", "reviewer"):
            owner = record.get(field)
            if isinstance(owner, dict) and bool(owner["contacts"]) != (owner["state"] == "assigned"):
                report(field, "contact list must correspond to assignment state")

        kind = record["record_type"]
        if kind in {"algorithm", "construction", "protocol"}:
            for field in ("spec_refs", "finding_refs"):
                for link in record[field]:
                    if link in records and records[link]["subject_ref"] != record_id:
                        report(field, f"{link} refers to a different subject")
        elif kind == "implementation":
            spec = records.get(record.get("spec_ref"))
            if spec and spec["subject_ref"] != record["subject_ref"]:
                report("spec_ref", "specification refers to a different subject")
            if record["origin"] == "upstream" and "source_sha256" not in record:
                report("source_sha256", "upstream implementations require a pinned source digest")
            if record["origin"] == "first-party" and "path" not in record:
                report("path", "first-party implementations require a source path")
        elif kind == "specification":
            if ("lean_module" in record) != ("path" in record):
                report("lean_module", "Lean module and source path must occur together")
        elif kind == "evidence-request":
            if bool(record["theorems"]) != (record["method"] == "formal"):
                report("theorems", "formal evidence requests must name the required theorems")
        elif kind == "evidence-result":
            request = records.get(record["request_ref"])
            if request:
                for field in ("subject_ref", "claim", "scope"):
                    if record[field] != request[field]:
                        report(field, "value differs from the evidence request")
                allowed_states = _FORMAL_STATES if request["method"] == "formal" else _RUN_STATES
                if record["state"] not in allowed_states:
                    report("state", f"invalid state for {request['method']} evidence")
                if record["state"] == "proved" and not set(request["theorems"]).issubset(record["observations"]):
                    report("observations", "proved evidence must list every required theorem")
            if record["state"] in _OBSERVED_STATES:
                for field in ("execution_sha256", "artifacts", "verifier", "observed_at", "observations"):
                    if not record.get(field):
                        report(field, "observed evidence requires a recorded execution and outputs")
            if record["state"] == "not_applicable" and not (record.get("reason") and record.get("reviewer")):
                report("state", "not_applicable evidence requires a reason and reviewer")
            if "observed_at" in record:
                try:
                    datetime.fromisoformat(record["observed_at"].replace("Z", "+00:00"))
                except ValueError:
                    report("observed_at", "invalid observation timestamp")
        elif kind == "release-set":
            policy = records.get(record["policy_ref"])
            if policy and policy["profile"] != record["profile"]:
                report("policy_ref", "release and policy profiles differ")
            if record["support_from"] > record["support_until"]:
                report("support_until", "support window ends before it starts")
            seen_packages = set()
            for package in record["packages"]:
                key = (package["ecosystem"], package["package_name"], package.get("build_target_ref"))
                if key in seen_packages:
                    report("packages", f"duplicate package {key}")
                seen_packages.add(key)
                binding = records.get(package["binding_ref"])
                if binding and any(package[field] != binding[field] for field in ("ecosystem", "package_name")):
                    report("packages", "package identity differs from the associated binding")
                if binding and "build_target_ref" in package and package["build_target_ref"] not in binding["target_refs"]:
                    report("packages", "recorded package target is outside the binding target matrix")
            if record["approval"] == "approved" and not (
                record.get("reviewer") and record["evidence_result_refs"]
            ):
                report("approval", "approval requires review and evidence references")
        elif kind in {"alias", "tombstone"}:
            field = "alias_id" if kind == "alias" else "retired_id"
            old_id = record[field]
            replacement = record.get("canonical_ref", record.get("replacement_ref"))
            if old_id in records or old_id in inactive:
                report(field, f"identifier already in use: {old_id}")
            if replacement and replacement.split(":")[1] != old_id.split(":")[1]:
                report(field, "replacement must have the same identity kind")
            inactive.add(old_id)
    return errors


def validate_records(repo: Path, entries):
    """Validate (source location, decoded record) pairs against the local schema."""
    schema = _schema(repo / "registry/schemas" / "registry.schema.json")
    definitions = schema["$defs"]
    kinds = {variant["$ref"].rsplit("/", 1)[1] for variant in schema["oneOf"]}
    errors = []
    records = {}
    locations = {}
    for location, record in entries:
        if not isinstance(record, dict):
            errors.append(f"{location}: expected a registry record object")
            continue
        kind = record.get("record_type")
        if not isinstance(kind, str) or kind not in kinds:
            errors.append(f"{location}/record_type: unknown record type {kind!r}")
            continue
        record_errors = _errors(record, definitions[kind], location, definitions)
        if record_errors:
            errors.extend(record_errors)
            continue
        record_id = record["id"]
        if record_id in records:
            errors.append(f"{location}/id: duplicate identifier {record_id!r} (also in {locations[record_id]})")
            continue
        records[record_id] = record
        locations[record_id] = location
    if not errors:
        errors = _semantic_errors(records, locations)
    if errors:
        raise RegistryValidationError(errors)
    ordered = [records[key] for key in sorted(records)]
    return {
        "schema_version": 1,
        "record_count": len(ordered),
        "counts": dict(sorted(Counter(record["record_type"] for record in ordered).items())),
        "records": ordered,
    }


def validate(repo: Path):
    """Load and validate all canonical JSON records under registry/."""
    root = repo.resolve()
    entries = []
    for path in sorted((root / "registry/records").rglob("*.json")):
        if path.suffix != ".json":
            continue
        if not path.resolve().is_relative_to(root / "registry/records"):
            raise RegistryValidationError([f"{path}: registry input escapes its directory"])
        entries.append((path.relative_to(root).as_posix(), _read_json(path)))
    if not entries:
        raise RegistryValidationError(["registry: no record files found"])
    return validate_records(root, entries)
