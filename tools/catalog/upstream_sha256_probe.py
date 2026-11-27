"""Check SHA-256 in the pinned CPython distribution's compiled HACL* C backend."""

import hashlib
import json
from pathlib import Path
import platform
import sys


REVISION = "df793163d5821791d4e7caf88885a2c11a107986"
LENGTHS = (0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 1024, 4096)


def run():
    tag = getattr(sys, "_git", ())
    if len(tag) != 3 or tag[:2] != ("CPython", "tags/v3.14.2") or not tag[2] or not REVISION.startswith(tag[2]):
        raise ValueError("this reproduction requires the CPython v3.14.2 release build")

    import _hashlib
    import _sha2

    if _sha2.sha256(b"abc").hexdigest() != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad":
        raise ValueError("NIST abc digest mismatch")

    for length in LENGTHS:
        message = bytes((index * 73 + length) % 256 for index in range(length))
        reference = _hashlib.openssl_sha256(message).digest()
        candidate = _sha2.sha256()
        for offset in range(0, length, 17):
            candidate.update(message[offset:offset + 17])
        if _sha2.sha256(message).digest() != reference or candidate.digest() != reference:
            raise ValueError(f"upstream SHA-256 mismatch at {length} bytes")

    result = {
        "revision": REVISION,
        "observed_build": sys.version,
        "platform": platform.platform(),
        "backend": "CPython _sha2.sha256",
        "module_origin": _sha2.__spec__.origin,
        "oracle": "CPython _hashlib.openssl_sha256",
        "checked_byte_lengths": LENGTHS,
        "check": "published NIST vector and functional byte agreement",
    }
    if sys.platform == "win32":
        library = Path(sys.base_prefix) / "python314.dll"
        if library.is_file():
            with library.open("rb") as source:
                result["python314_dll_sha256"] = hashlib.file_digest(source, "sha256").hexdigest()
    return result


if __name__ == "__main__":
    try:
        print(json.dumps(run(), indent=2))
    except (ImportError, OSError, ValueError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        raise SystemExit(1) from error
