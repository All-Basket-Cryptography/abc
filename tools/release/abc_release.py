"""Prepare and independently replay unsigned local research release sets."""

from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from tools.release.abc_package import consumer_test, package
from tools.verification.abc_runner import _digest, _file_digest, _within, _write_json
from tools.catalog.abc_status import read_json


RESEARCH_SDKS = {"rust", "npm"}
BOM_NAME = "sbom.cdx.json"
MANIFEST_NAME = "release-set.json"
PROVENANCE_NAME = "provenance.json"
VERSION = "0.1.0"


def _source(repo):
    outcome = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=repo, text=True, capture_output=True)
    revision = outcome.stdout.strip() if outcome.returncode == 0 else None
    files = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=repo)
    contents = {}
    for name in sorted(set(files.decode("utf-8").split("\0")) - {""}):
        path = _within(repo, name)
        if (repo / name).is_symlink():
            raise ValueError(f"Cannot build from symbolic source {name!r}")
        contents[name] = _file_digest(path)
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo))
    return {"revision": revision, "dirty": dirty, "source_digest": _digest(contents), "files": contents}


def _build(repo, sdk, directory):
    with TemporaryDirectory(prefix="abc-clean-build-") as output:
        artifact = Path(package(repo, sdk, directory, Path(output))["file"])
        result = consumer_test(repo, sdk, artifact)
    return {"sdk": sdk, "file": artifact.name, "checks": result["checks"], **_file_digest(artifact)}


def _bom(artifacts):
    root = {"type": "application", "name": "All-Basket Cryptography research distribution", "version": VERSION, "bom-ref": "abc-research"}
    core = {"type": "library", "name": "abc-sha256", "version": VERSION, "bom-ref": "abc-sha256"}
    components = [core]
    dependencies = [{"ref": root["bom-ref"], "dependsOn": [f"sdk-{entry['sdk']}" for entry in artifacts]},
                    {"ref": core["bom-ref"], "dependsOn": []}]
    for entry in artifacts:
        reference = f"sdk-{entry['sdk']}"
        components.append({"type": "file", "name": entry["file"], "version": VERSION, "bom-ref": reference,
                           "hashes": [{"alg": "SHA-256", "content": entry["sha256"]}]})
        dependencies.append({"ref": reference, "dependsOn": [core["bom-ref"]]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": {"component": root},
            "components": components, "dependencies": dependencies}


def _provenance(source, artifacts):
    return {"schema_version": 1, "scope": "local-research-replay", "source": source,
            "subjects": [{"file": entry["file"], "sha256": entry["sha256"]} for entry in artifacts],
            "recipe": {"entry": "python -m tools.abc_cli release prepare", "profile": "research", "sdks": [entry["sdk"] for entry in artifacts]}}


def prepare(repo, directory, profile, sdks):
    if profile != "research":
        raise ValueError("Production release is closed pending independent approval and verified proofs")
    if not sdks or not set(sdks) <= RESEARCH_SDKS or len(sdks) != len(set(sdks)):
        raise ValueError("Release requires unique supported research SDKs")
    source = _source(repo)
    directory.mkdir(parents=True, exist_ok=False)
    artifacts = [_build(repo, sdk, directory) for sdk in sorted(sdks)]
    if source != _source(repo):
        raise ValueError("Repository inputs changed during packaging")
    _write_json(directory / BOM_NAME, _bom(artifacts))
    _write_json(directory / PROVENANCE_NAME, _provenance(source, artifacts))
    release = {"schema_version": 1, "profile": profile, "production_approved": False, "source_digest": source["source_digest"],
               "artifacts": artifacts, "auxiliary": {name: _file_digest(directory / name) for name in (BOM_NAME, PROVENANCE_NAME)}}
    _write_json(directory / MANIFEST_NAME, release)
    return {"manifest": str(directory / MANIFEST_NAME), **release}


def verify(repo, manifest_path):
    release = read_json(manifest_path)
    if (not isinstance(release, dict) or release.get("schema_version") != 1 or release.get("profile") != "research"
            or release.get("production_approved") is not False):
        raise ValueError("Expected a research manifest with production approval closed")
    source = _source(repo)
    if release.get("source_digest") != source["source_digest"]:
        raise ValueError("Release source digest is stale")
    directory = manifest_path.resolve().parent
    artifacts = release["artifacts"]
    sdks = [entry["sdk"] for entry in artifacts]
    if sdks != sorted(set(sdks)) or not sdks or not set(sdks) <= RESEARCH_SDKS:
        raise ValueError("Unexpected release SDK set")
    for entry in artifacts:
        original = _within(directory, entry["file"])
        if original.parent != directory or _file_digest(original) != {key: entry[key] for key in ("sha256", "size_bytes")}:
            raise ValueError(f"Artifact bytes differ from the manifest: {entry['file']}")
    auxiliary = {name: _file_digest(directory / name) for name in (BOM_NAME, PROVENANCE_NAME)}
    if (auxiliary != release["auxiliary"] or read_json(directory / BOM_NAME) != _bom(artifacts)
            or read_json(directory / PROVENANCE_NAME) != _provenance(source, artifacts)):
        raise ValueError("SBOM or provenance does not match the selected release")
    with TemporaryDirectory(prefix="abc-release-replay-") as stage:
        replay = [_build(repo, sdk, Path(stage)) for sdk in sdks]
    if replay != artifacts or _source(repo) != source:
        raise ValueError("Independent local rebuild did not reproduce the manifest and consumer results")
    return {"status": "verified", "profile": "research", "production_approved": False, "artifacts": artifacts}
