"""Validate the selected FIPS 203 ACVP vectors and their source metadata."""

import argparse
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
REVISION = "975de31eb83d87039ec88934fdc47d8c312b892d"
SOURCES = {
    "keygen": ("ML-KEM-keyGen-FIPS203", "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b"),
    "encapdecap": ("ML-KEM-encapDecap-FIPS203", "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f"),
}
CASES = {
    ("keygen", 2, 26): "keygen",
    ("keygen", 2, 27): "keygen",
    ("encapdecap", 2, 26): "encap",
    ("encapdecap", 2, 27): "encap",
    ("encapdecap", 5, 86): "decap",
    ("encapdecap", 5, 88): "decap",
    ("encapdecap", 9, 128): "reject_dk",
    ("encapdecap", 10, 137): "reject_ek",
}
FIELDS = {
    "keygen": ("d", "z", "ek", "dk"),
    "encap": ("ek", "m", "c", "k"),
    "decap": ("dk", "c", "k"),
    "reject_dk": ("dk",),
    "reject_ek": ("ek",),
}
LENGTH = {"d": 32, "z": 32, "ek": 1184, "dk": 2400, "m": 32, "c": 1088, "k": 32}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical_key(key):
    for offset in range(0, len(key) - 32, 3):
        a, b, c = key[offset:offset + 3]
        if (a | ((b & 15) << 8)) >= 3329 or ((b >> 4) | (c << 4)) >= 3329:
            return False
    return True


def check_fixtures(upstream=None):
    data = json.loads((HERE / "acvp.json").read_text(encoding="ascii"))
    require(data["revision"] == REVISION and data["sources"].keys() == SOURCES.keys(), "source metadata")
    documents = {}
    for name, (stem, digest) in SOURCES.items():
        expected_url = (f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{REVISION}"
                        f"/gen-val/json-files/{stem}/internalProjection.json")
        require(data["sources"][name] == {"url": expected_url, "sha256": digest}, f"source pin: {name}")
        if upstream is not None:
            original = (upstream / f"{stem}-internalProjection.json").read_bytes()
            require(hashlib.sha256(original).hexdigest() == digest, f"source bytes: {name}")
            documents[name] = json.loads(original)["testGroups"]

    seen = set()
    for case in data["cases"]:
        identity = (case["source"], case["tgId"], case["tcId"])
        operation = CASES.get(identity)
        require(identity not in seen and operation == case["operation"], f"unexpected fixture {identity}")
        seen.add(identity)
        names = FIELDS[operation]
        require(set(case) == {"source", "tgId", "tcId", "operation", *names}, "fixture fields")
        fields = {name: bytes.fromhex(case[name]) for name in names}
        for name, content in fields.items():
            require(len(content) == LENGTH[name] and content.hex() == case[name], f"fixture field {name}")

        if documents:
            groups = documents[case["source"]]
            group = next(group for group in groups if group["tgId"] == case["tgId"])
            require(group["parameterSet"] == "ML-KEM-768", "upstream parameter set")
            original = next(item for item in group["tests"] if item["tcId"] == case["tcId"])
            require(all(bytes.fromhex(original[name]) == fields[name] for name in names), "projection mismatch")

        if "ek" in fields:
            require(canonical_key(fields["ek"]) == (operation != "reject_ek"), "encapsulation key modulus")
        if "dk" in fields:
            key = fields["dk"]
            embedded = key[1152:2336]
            require((hashlib.sha3_256(embedded).digest() == key[2336:2368]) == (operation != "reject_dk"),
                    "decapsulation key digest")
            if operation == "keygen":
                require(embedded == fields["ek"] and key[-32:] == fields["z"], "keygen embedded fields")
            if operation == "decap":
                implicit = hashlib.shake_256(key[-32:] + fields["c"]).digest(32)
                require((implicit == fields["k"]) == (case["tcId"] == 88), "implicit rejection vector")
    require(seen == set(CASES), "missing selected fixture")
    return data["cases"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, help="directory containing both pinned ACVP JSON files")
    options = parser.parse_args()
    cases = check_fixtures(options.upstream)
    print(json.dumps({"status": "passed", "fixtures": len(cases), "upstream_checked": options.upstream is not None}))
